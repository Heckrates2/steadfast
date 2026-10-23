//! Minimaler HTTP-Lastgenerator fuer die REST-Engine.
//!
//! Nutzt einen Hyper-Client mit Keep-Alive-Pool (so viele offene Verbindungen
//! wie `--connections` Worker-Tasks) und misst End-to-End-Latenzen inkl.
//! Response-Body (nur vollstaendig gelesene Responses geben die Verbindung
//! zurueck in den Pool — genau wie echte Clients).
//!
//! Usage:
//!   loadtest --url http://127.0.0.1:8080/todo_app/tasks [--duration 10]
//!            [--requests N] [--connections 32] [--method GET] [--body "{...}"]
//!            [--header "x-api-key: ..."] (wiederholbar)
//!
//! Ohne `--requests` laeuft der Test fuer `--duration` Sekunden. Mit
//! `--requests N` werden genau N Requests gefahren (deterministisch, z. B.
//! zum Seeden einer Kollektion vor den Messlaeufen).
//!
//! Hinweis: Generator und Server teilen sich hier dieselbe Maschine — die
//! Zahlen sind damit eine Untergrenze dessen, was ein dedizierter Host misst.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::http::{HeaderName, HeaderValue, Method, Request};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;

struct Args {
    url: String,
    duration: Duration,
    requests: Option<u64>,
    connections: usize,
    method: Method,
    body: Option<String>,
    headers: Vec<(HeaderName, HeaderValue)>,
}

fn parse_args() -> Result<Args, String> {
    let mut url: Option<String> = None;
    let mut duration_secs: u64 = 10;
    let mut requests: Option<u64> = None;
    let mut connections: usize = 32;
    let mut method: Option<String> = None;
    let mut body: Option<String> = None;
    let mut headers: Vec<(HeaderName, HeaderValue)> = Vec::new();

    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = |what: &str| -> Result<String, String> {
            it.next()
                .ok_or_else(|| format!("{what} erwartet einen Wert"))
        };
        match flag.as_str() {
            "--url" => url = Some(value("--url")?),
            "--duration" => {
                duration_secs = value("--duration")?
                    .parse()
                    .map_err(|_| "--duration muss eine Zahl sein")?
            }
            "--requests" => {
                requests = Some(
                    value("--requests")?
                        .parse()
                        .map_err(|_| "--requests muss eine Zahl sein")?,
                )
            }
            "--connections" => {
                connections = value("--connections")?
                    .parse()
                    .map_err(|_| "--connections muss eine Zahl sein")?
            }
            "--method" => method = Some(value("--method")?),
            "--body" => body = Some(value("--body")?),
            "--header" => {
                let raw = value("--header")?;
                let (name, val) = raw
                    .split_once(':')
                    .ok_or_else(|| format!("--header erwartet \"Name: Wert\", got `{raw}`"))?;
                headers.push((
                    name.trim()
                        .parse()
                        .map_err(|_| format!("ungueltiger Header-Name `{}`", name.trim()))?,
                    val.trim()
                        .parse()
                        .map_err(|_| format!("ungueltiger Header-Wert `{}`", val.trim()))?,
                ));
            }
            other => return Err(format!("unbekanntes Argument `{other}`")),
        }
    }

    let url = url.ok_or("--url ist erforderlich")?;
    let method = Method::from_bytes(
        method
            .unwrap_or_else(|| "GET".to_string())
            .to_uppercase()
            .as_bytes(),
    )
    .map_err(|e| e.to_string())?;

    Ok(Args {
        url,
        duration: Duration::from_secs(duration_secs.max(1)),
        requests,
        connections: connections.max(1),
        method,
        body,
        headers,
    })
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("Fehler: {err}\n\nsiehe Moduldokumentation (`--help`)");
            std::process::exit(2);
        }
    };

    let requests = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    // Statusklassen 2xx..5xx.
    let classes: [Arc<AtomicU64>; 4] = Default::default();

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());

    let mut builder = Request::builder()
        .method(args.method.clone())
        .uri(&args.url);
    for (name, value) in &args.headers {
        builder = builder.header(name, value);
    }
    if args.body.is_some()
        && !args
            .headers
            .iter()
            .any(|(n, _)| n.as_str() == "content-type")
    {
        builder = builder.header("content-type", "application/json");
    }
    let template = builder
        .body(Full::new(Bytes::from(
            args.body.clone().unwrap_or_default(),
        )))
        .expect("statisches Request-Template ist immer gueltig");

    println!(
        "Lasttest: {} {} | {} Verbindungen | {}",
        args.method,
        args.url,
        args.connections,
        match args.requests {
            Some(n) => format!("{n} Requests (fest)"),
            None => format!("{} s", args.duration.as_secs()),
        }
    );

    let start = Instant::now();
    // Im Fest-Modus verteilen Tickets die exakte Request-Anzahl auf die Worker;
    // im Dauer-Modus bleibt der Zähler bei 0 und die Dauer entscheidet.
    let tickets = Arc::new(AtomicU64::new(0));
    let progress = if args.requests.is_none() {
        Some(tokio::spawn(progress_loop(
            Arc::clone(&requests),
            args.duration,
        )))
    } else {
        None
    };

    let mut handles = Vec::with_capacity(args.connections);
    for _ in 0..args.connections {
        let client = client.clone();
        let template = template.clone();
        let requests = Arc::clone(&requests);
        let errors = Arc::clone(&errors);
        let classes = classes.clone();
        let tickets = Arc::clone(&tickets);
        let target = args.requests;
        let duration = args.duration;
        handles.push(tokio::spawn(async move {
            let mut latencies_us: Vec<u64> = Vec::with_capacity(16_384);
            loop {
                if let Some(n) = target {
                    if tickets.fetch_add(1, Ordering::Relaxed) >= n {
                        break;
                    }
                } else if start.elapsed() >= duration {
                    break;
                }
                let t0 = Instant::now();
                match client.request(template.clone()).await {
                    Ok(response) => {
                        let class = (response.status().as_u16() / 100).clamp(2, 5) as usize - 2;
                        // Body vollstaendig lesen, sonst landet die Verbindung
                        // nicht zurueck im Keep-Alive-Pool.
                        let _ = response.into_body().collect().await;
                        classes[class].fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
                latencies_us.push(t0.elapsed().as_micros() as u64);
                requests.fetch_add(1, Ordering::Relaxed);
            }
            latencies_us
        }));
    }

    let mut all: Vec<u64> = Vec::new();
    for handle in handles {
        all.extend(handle.await.expect("worker darf nicht paniken"));
    }
    if let Some(progress) = progress {
        progress.abort();
    }

    let wall = start.elapsed();
    let total = requests.load(Ordering::Relaxed);
    let failed = errors.load(Ordering::Relaxed);

    println!("\n--- Ergebnis ---");
    println!("Dauer:            {:.2} s", wall.as_secs_f64());
    println!(
        "Requests:         {total} ({:.0} RPS)",
        total as f64 / wall.as_secs_f64()
    );
    println!("Verbindungsfehler: {failed}");
    for (index, label) in ["2xx", "3xx", "4xx", "5xx"].iter().enumerate() {
        let count = classes[index].load(Ordering::Relaxed);
        if count > 0 {
            println!("Status {label}:        {count}");
        }
    }

    if all.is_empty() {
        println!("Keine Requests gemessen.");
        return;
    }
    all.sort_unstable();
    println!("Latenz p50:  {}", fmt_us(all[all.len() / 2]));
    println!("Latenz p90:  {}", fmt_us(percentile(&all, 90)));
    println!("Latenz p99:  {}", fmt_us(percentile(&all, 99)));
    println!("Latenz max:  {}", fmt_us(all[all.len() - 1]));
}

fn percentile(sorted: &[u64], p: u64) -> u64 {
    let index = ((p as f64 / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

fn fmt_us(micros: u64) -> String {
    if micros >= 1_000 {
        format!("{:.2} ms", micros as f64 / 1_000.0)
    } else {
        format!("{micros} us")
    }
}

async fn progress_loop(requests: Arc<AtomicU64>, duration: Duration) {
    let start = Instant::now();
    let mut last = 0u64;
    while start.elapsed() < duration {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let now = requests.load(Ordering::Relaxed);
        println!("  {now} Requests ({}/s in der letzten Sekunde)", now - last);
        last = now;
    }
}
