//! End-to-end pipeline tests against mocked FFmpeg and Telegram services.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use secrecy::SecretString;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use super::jobs::{self, Created, NewJob, SourceKind};
use super::service::MediaService;
use super::spec::{Action, JobOptions};
use crate::config::{Config, Destination};
use crate::db::Db;
use crate::extract::Extractor;
use crate::fetch::Fetcher;
use crate::ffmpeg::FfmpegClient;
use crate::telegram::client::Bot;

const METADATA: &str = r#"{"format":"mov,mp4,m4a,3gp,3g2,mj2","duration_seconds":5.0,"width":1280,"height":720,"video_codec":"h264","audio_codec":"aac","channels":2,"still_image":false}"#;

fn completed_job(id: char, bytes: &[u8], content_type: &str) -> Value {
    json!({ "api_version": "1", "instance_id": "inst", "job_id": id.to_string().repeat(32), "status": "completed",
            "status_url": format!("/v1/jobs/{}", id.to_string().repeat(32)),
            "result": { "content_type": content_type, "size_bytes": bytes.len(), "sha256": hex::encode(Sha256::digest(bytes)) },
            "error": null })
}

/// FFmpeg service that completes every job immediately and records the
/// operations it was asked for.
async fn ffmpeg_service(ops: Arc<Mutex<Vec<Value>>>) -> MockServer {
    let server = MockServer::start().await;
    let video = json!([
        "width",
        "height",
        "fit",
        "quality",
        "audio_bitrate_kbps",
        "audio_mode",
        "max_dimension",
        "max_fps",
        "max_bitrate_kbps"
    ]);
    Mock::given(method("GET"))
        .and(path("/v1/capabilities"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "api_version": "1", "instance_id": "inst",
            "operations": { "metadata": ["json"], "transcode": ["mp4", "webm"], "remux": ["mp4", "webm"], "trim": ["mp4", "webm"], "thumbnail": ["jpg", "png"] },
            "parameters": { "transcode": video, "remux": ["audio_mode"], "metadata": [],
                            "thumbnail": ["timestamp_seconds", "width", "height", "fit", "jpeg_quality"] },
            "limits": { "max_upload_bytes": 1_000_000, "max_jobs_per_consumer": 2, "max_duration_seconds": 600 } })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/jobs"))
        .respond_with(move |req: &Request| {
            let body = String::from_utf8_lossy(&req.body);
            let start = body.find('{').unwrap();
            let end = body[start..].find("\r\n").unwrap() + start;
            let spec: Value = serde_json::from_str(&body[start..end]).unwrap();
            let op = spec["operation"].as_str().unwrap().to_owned();
            ops.lock().unwrap().push(spec);
            let job = match op.as_str() {
                "metadata" => completed_job('a', METADATA.as_bytes(), "application/json"),
                "thumbnail" => completed_job('c', b"JPEGDATA", "image/jpeg"),
                _ => completed_job('b', b"ENCODED-VIDEO", "video/mp4"),
            };
            ResponseTemplate::new(202).set_body_json(job)
        })
        .mount(&server)
        .await;
    for (id, bytes) in [
        ('a', METADATA.as_bytes().to_vec()),
        ('b', b"ENCODED-VIDEO".to_vec()),
        ('c', b"JPEGDATA".to_vec()),
    ] {
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1/jobs/{}/download",
                id.to_string().repeat(32)
            )))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
            .mount(&server)
            .await;
    }
    Mock::given(method("DELETE"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    server
}

async fn telegram() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/botTOKEN/\w+$"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "ok": true, "result": {
            "message_id": 900, "date": 1, "chat": { "id": -100555, "type": "supergroup" } } })),
        )
        .mount(&server)
        .await;
    server
}

struct Harness {
    svc: Arc<MediaService>,
    _work: tempfile::TempDir,
    ops: Arc<Mutex<Vec<Value>>>,
    tg: MockServer,
    _ff: MockServer,
}

async fn harness() -> Harness {
    crate::http::init_tls();
    let work = tempfile::tempdir().unwrap();
    let ops = Arc::new(Mutex::new(Vec::new()));
    let ff = ffmpeg_service(ops.clone()).await;
    let tg = telegram().await;
    let mut config: Config = figment::Figment::new().extract().unwrap();
    config.storage.work_dir = work.path().to_owned();
    config.destinations.insert(
        "ops".into(),
        Destination {
            chat_id: -100555,
            thread_id: Some(3),
        },
    );
    config.ffmpeg.queue_allowance_secs = 10;
    let config = Arc::new(config);
    let db = Db::open_in_memory().await.unwrap();
    let client = Arc::new(
        FfmpegClient::new(
            &ff.uri(),
            SecretString::from("k"),
            db.clone(),
            config.ffmpeg.clone(),
        )
        .unwrap(),
    );
    client.refresh_capabilities().await.unwrap();
    let fetcher = Arc::new(Fetcher::for_tests());
    let svc = Arc::new(MediaService {
        db,
        config: config.clone(),
        ffmpeg: Some(client),
        extractor: Arc::new(Extractor::new(fetcher.clone(), &config.fetch).unwrap()),
        fetcher,
        bot: Some(Arc::new(Bot::new(
            crate::http::client(),
            &tg.uri(),
            SecretString::from("TOKEN"),
        ))),
        wake: Arc::new(Notify::new()),
        running: Mutex::new(Default::default()),
    });
    Harness {
        svc,
        _work: work,
        ops,
        tg,
        _ff: ff,
    }
}

async fn upload_job(svc: &MediaService, action: Action, options: JobOptions) -> String {
    let id = jobs::new_id();
    let dir = svc.job_dir(&id);
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let src = dir.join("source");
    tokio::fs::write(&src, b"original upload bytes")
        .await
        .unwrap();
    let created = jobs::create(
        &svc.db,
        id,
        NewJob {
            owner_kind: "api",
            owner_id: "media".into(),
            idempotency_key: Some("key-1".into()),
            request_hash: Some("h".into()),
            action,
            options,
            source_kind: SourceKind::Upload,
            source_ref: "clip.mp4".into(),
            source_path: Some(src.to_string_lossy().into_owned()),
            input_bytes: Some(21),
            destination: Some("ops".into()),
            chat_id: Some(-100555),
            thread_id: Some(3),
            reply_to: None,
            status_message: None,
        },
    )
    .await
    .unwrap();
    let Created::New(id) = created else { panic!() };
    id
}

async fn run_until_done(svc: Arc<MediaService>, id: &str) -> jobs::JobRow {
    let stop = CancellationToken::new();
    let worker = tokio::spawn(super::pipeline::run_worker(
        svc.clone(),
        "test".into(),
        stop.clone(),
    ));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let job = loop {
        let j = jobs::get(&svc.db, id).await.unwrap().unwrap();
        if !j.is_active() || tokio::time::Instant::now() > deadline {
            break j;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    stop.cancel();
    let _ = worker.await;
    job
}

#[tokio::test]
async fn gif_upload_is_encoded_and_sent_as_an_animation() {
    let h = harness().await;
    let id = upload_job(&h.svc, Action::Gif, JobOptions::default()).await;
    let job = run_until_done(h.svc.clone(), &id).await;
    assert_eq!(
        job.state, "completed",
        "{:?} {:?}",
        job.error_code, job.error_message
    );

    let ops = h.ops.lock().unwrap().clone();
    let names: Vec<&str> = ops
        .iter()
        .map(|o| o["operation"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["metadata", "transcode", "thumbnail"]);
    let p = &ops[1]["parameters"];
    assert_eq!(
        (
            p["audio_mode"].as_str(),
            p["max_dimension"].as_u64(),
            p["max_fps"].as_u64(),
            p["quality"].as_u64()
        ),
        (Some("remove"), Some(640), Some(15), Some(28))
    );
    assert!(p["max_bitrate_kbps"].as_u64().unwrap() > 1000);
    // The thumbnail is taken from the 640x360 result, within Telegram's 320 px.
    assert_eq!(
        (
            ops[2]["parameters"]["width"].as_u64(),
            ops[2]["parameters"]["height"].as_u64()
        ),
        (Some(320), Some(180))
    );

    let sent: Vec<(String, String)> =
        h.tg.received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r.url.path().rsplit('/').next().unwrap().to_owned(),
                    String::from_utf8_lossy(&r.body).into_owned(),
                )
            })
            .collect();
    let (_, body) = sent
        .iter()
        .find(|(m, _)| m == "sendAnimation")
        .expect("sent as an animation");
    for needle in [
        "name=\"animation\"",
        "attach://thumb",
        "name=\"thumb\"",
        "ENCODED-VIDEO",
        "JPEGDATA",
        "-100555",
        "message_thread_id",
    ] {
        assert!(body.contains(needle), "missing {needle}");
    }
    // API jobs keep the result for download.
    let kept = job.result_path.expect("result retained for the API owner");
    assert_eq!(tokio::fs::read(&kept).await.unwrap(), b"ENCODED-VIDEO");
    assert!(
        !h.svc.job_dir(&id).join("source").exists(),
        "the source is removed after delivery"
    );
    assert_eq!(job.result_size, Some(13));
}

#[tokio::test]
async fn compatible_mp4_is_remuxed_and_metadata_is_cached() {
    let h = harness().await;
    let first = upload_job(&h.svc, Action::Mp4, JobOptions::default()).await;
    assert_eq!(
        run_until_done(h.svc.clone(), &first).await.state,
        "completed"
    );
    // The same input again: metadata comes from the cache.
    let mut second = NewJob {
        idempotency_key: Some("key-2".into()),
        ..sample_upload(&h.svc).await
    };
    second.action = Action::Mp4;
    let Created::New(id2) = jobs::create(&h.svc.db, jobs::new_id(), second)
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(run_until_done(h.svc.clone(), &id2).await.state, "completed");
    let names: Vec<String> = h
        .ops
        .lock()
        .unwrap()
        .iter()
        .map(|o| o["operation"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(names.iter().filter(|n| *n == "metadata").count(), 1);
    assert_eq!(names.iter().filter(|n| *n == "remux").count(), 2);
}

async fn sample_upload(svc: &MediaService) -> NewJob {
    let dir = svc.config.storage.work_dir.join("second");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let src = dir.join("source");
    tokio::fs::write(&src, b"original upload bytes")
        .await
        .unwrap();
    NewJob {
        owner_kind: "api",
        owner_id: "media".into(),
        idempotency_key: None,
        request_hash: None,
        action: Action::Mp4,
        options: JobOptions::default(),
        source_kind: SourceKind::Upload,
        source_ref: "clip.mp4".into(),
        source_path: Some(src.to_string_lossy().into_owned()),
        input_bytes: Some(21),
        destination: None,
        chat_id: None,
        thread_id: None,
        reply_to: None,
        status_message: None,
    }
}

#[tokio::test]
async fn overlong_gif_fails_with_a_trim_prompt_and_cleans_up() {
    let h = harness().await;
    // 45 s exceeds the 30 s GIF limit.
    let id = upload_job(
        &h.svc,
        Action::Gif,
        JobOptions {
            duration_seconds: Some(45.0),
            ..Default::default()
        },
    )
    .await;
    let job = run_until_done(h.svc.clone(), &id).await;
    // Options validation normally rejects this earlier; the pipeline checks too.
    assert_eq!(job.state, "failed");
    assert!(job.error_message.unwrap().contains("start="));
    assert!(!h.svc.job_dir(&id).exists());
}

mod api_flow {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;
    use crate::api::{self, AppState, auth};
    use crate::config::{ConsumerConfig, Scope};

    const KEY: &str = "media-consumer-key-0123456789";
    const OTHER: &str = "other-consumer-key-0123456789";

    fn state(h: &Harness) -> AppState {
        let mut config = (*h.svc.config).clone();
        config.consumers = vec![
            ConsumerConfig {
                id: "media".into(),
                key_sha256: vec![hex::encode(auth::sha256(KEY.as_bytes()))],
                scopes: vec![Scope::Media],
                destinations: vec!["ops".into()],
            },
            ConsumerConfig {
                id: "other".into(),
                key_sha256: vec![hex::encode(auth::sha256(OTHER.as_bytes()))],
                scopes: vec![Scope::Media],
                destinations: vec![],
            },
        ];
        AppState {
            consumers: Arc::new(auth::Consumers::new(&config.consumers)),
            config: Arc::new(config),
            db: h.svc.db.clone(),
            outbox: Arc::new(Notify::new()),
            status: h.svc.clone(),
            media: Some(h.svc.clone()),
        }
    }

    async fn send(
        state: &AppState,
        req: Request<Body>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let res = api::router(state.clone()).oneshot(req).await.unwrap();
        let (parts, body) = res.into_parts();
        (
            parts.status,
            parts.headers,
            body.collect().await.unwrap().to_bytes().to_vec(),
        )
    }

    fn upload(key: &str, idem: &str, size: usize, data: &[u8]) -> Request<Body> {
        let b = "BOUNDARY42";
        let request = json!({ "action": "gif", "size_bytes": size, "destination": "ops", "preset": "telegram-gif" });
        let mut body = format!("--{b}\r\nContent-Disposition: form-data; name=\"request\"\r\nContent-Type: application/json\r\n\r\n{request}\r\n--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.mp4\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
        body.extend_from_slice(data);
        body.extend_from_slice(format!("\r\n--{b}--\r\n").as_bytes());
        Request::post("/v1/media/uploads")
            .header("authorization", format!("Bearer {key}"))
            .header("idempotency-key", idem)
            .header("content-type", format!("multipart/form-data; boundary={b}"))
            .body(Body::from(body))
            .unwrap()
    }

    fn get(uri: &str, key: &str) -> Request<Body> {
        Request::get(uri)
            .header("authorization", format!("Bearer {key}"))
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn upload_status_download_and_isolation() {
        let h = harness().await;
        let s = state(&h);
        // Declared size must match the bytes sent.
        assert_eq!(
            send(&s, upload(KEY, "upload-key-0001", 99, b"0123456789"))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let (status, headers, body) =
            send(&s, upload(KEY, "upload-key-0002", 10, b"0123456789")).await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let created: Value = serde_json::from_slice(&body).unwrap();
        let id = created["job_id"].as_str().unwrap().to_owned();
        assert_eq!(headers["location"], format!("/v1/jobs/{id}").as_str());
        // A replay returns the same job.
        let (status, _, body) = send(&s, upload(KEY, "upload-key-0002", 10, b"0123456789")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["job_id"],
            id.as_str()
        );

        let job = run_until_done(h.svc.clone(), &id).await;
        assert_eq!(job.state, "completed", "{:?}", job.error_message);
        let (status, _, body) = send(&s, get(&format!("/v1/jobs/{id}"), KEY)).await;
        assert_eq!(status, StatusCode::OK);
        let view: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(view["state"], "completed");
        assert_eq!(
            view["download_url"],
            format!("/v1/jobs/{id}/download").as_str()
        );
        let (status, headers, bytes) = send(&s, get(&format!("/v1/jobs/{id}/download"), KEY)).await;
        assert_eq!(
            (status, bytes.as_slice()),
            (StatusCode::OK, b"ENCODED-VIDEO".as_slice())
        );
        assert!(
            headers["content-disposition"]
                .to_str()
                .unwrap()
                .starts_with("attachment")
        );
        // Another consumer cannot see, download or delete it.
        for req in [
            get(&format!("/v1/jobs/{id}"), OTHER),
            get(&format!("/v1/jobs/{id}/download"), OTHER),
        ] {
            assert_eq!(send(&s, req).await.0, StatusCode::NOT_FOUND);
        }
        let del = |key: &str| {
            Request::delete(format!("/v1/jobs/{id}"))
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(send(&s, del(OTHER)).await.0, StatusCode::NOT_FOUND);
        assert_eq!(send(&s, del(KEY)).await.0, StatusCode::NO_CONTENT);
        assert_eq!(
            send(&s, get(&format!("/v1/jobs/{id}/download"), KEY))
                .await
                .0,
            StatusCode::GONE
        );
    }

    #[tokio::test]
    async fn json_jobs_require_idempotency_and_valid_targets() {
        let h = harness().await;
        let s = state(&h);
        let post = |key: &str, idem: Option<&str>, body: Value| {
            let mut r = Request::post("/v1/media/jobs")
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json");
            if let Some(i) = idem {
                r = r.header("idempotency-key", i);
            }
            r.body(Body::from(body.to_string())).unwrap()
        };
        let body = json!({ "source": { "url": "https://fixupx.com/example/status/123456789" }, "action": "gif",
                           "preset": "telegram-gif", "destination": "ops", "options": { "start_seconds": 3, "duration_seconds": 8 } });
        assert_eq!(
            send(&s, post(KEY, None, body.clone())).await.0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            send(&s, post(KEY, Some("json-key-0001"), body.clone()))
                .await
                .0,
            StatusCode::ACCEPTED
        );
        let mut changed = body.clone();
        changed["options"]["duration_seconds"] = json!(9);
        assert_eq!(
            send(&s, post(KEY, Some("json-key-0001"), changed)).await.0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            send(&s, post(OTHER, Some("json-key-0002"), body.clone()))
                .await
                .0,
            StatusCode::FORBIDDEN,
            "no access to ops"
        );
        let mut bad_preset = body.clone();
        bad_preset["preset"] = json!("compress-small");
        assert_eq!(
            send(&s, post(KEY, Some("json-key-0003"), bad_preset))
                .await
                .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let mut http = body;
        http["source"]["url"] = json!("http://x.com/a/status/1");
        assert_eq!(
            send(&s, post(KEY, Some("json-key-0004"), http)).await.0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
}
