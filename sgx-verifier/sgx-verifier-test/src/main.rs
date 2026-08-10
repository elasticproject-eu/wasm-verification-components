use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use clap::Parser;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Store};
use wasmtime_wasi::p2::{IoView, WasiCtx, WasiCtxBuilder, WasiView};

wasmtime::component::bindgen!({
    path: "../sgx-verifier-component/wit",
    world: "verifier",
});

use exports::trustee::verifier::verifier_interface as iface;

const SGX_COLLATERAL_MEDIA_TYPE: &str = "application/vnd.trustmee.sgx-collateral+cbor";

#[derive(Parser, Debug)]
#[command(name = "sgx-verifier-test")]
struct Args {
    /// Path to the Wasm component (`.wasm`) built by `cargo build --target wasm32-wasip2 --release`.
    #[arg(long)]
    component: PathBuf,

    /// Path to an SGX quote (raw bytes).
    #[arg(long)]
    quote: PathBuf,

    /// Optional path to CBOR-encoded dcap-qvl QuoteCollateralV3.
    #[arg(long)]
    collateral: Option<PathBuf>,

    /// Base cache directory on the host; a fresh subdirectory is pre-opened to the guest as `cache/`.
    #[arg(long, default_value = ".sgx-verifier-cache")]
    cache_dir: PathBuf,

    /// Expected REPORT_DATA binding (hex string, <= 64 bytes; zero-padded to 64).
    #[arg(long)]
    expected_report_data_hex: Option<String>,

    /// Expected CONFIGID binding (hex string, <= 64 bytes; zero-padded to 64).
    #[arg(long)]
    expected_init_data_hash_hex: Option<String>,
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).context("decode hex")
}

static CACHE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_cache_dir(base: &Path) -> Result<PathBuf> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let nanos = now.as_nanos();
    let seq = CACHE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = base.join(format!("dcap-qvl-cache-{nanos:x}-{pid}-{seq}"));
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(dir)
}

fn infer_media_type(bytes: &[u8]) -> &'static str {
    if bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte == b'{' || byte == b'[')
        .unwrap_or(false)
    {
        "application/json"
    } else {
        "application/octet-stream"
    }
}

/// Inputs for one evaluation of the SGX verifier component.
#[derive(Default)]
struct Evaluation {
    /// Raw SGX quote bytes; wrapped into the `{"quote": base64}` evidence document.
    quote: Vec<u8>,
    /// CBOR-encoded `QuoteCollateralV3`, passed as an endorsement. When absent the
    /// component fetches collateral from Intel PCS over WASI-HTTP.
    collateral: Option<Vec<u8>>,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
}

/// Loads the component once and evaluates quotes against it.
struct Runner {
    engine: wasmtime::Engine,
    component: Component,
    cache_base: PathBuf,
}

impl Runner {
    fn new(component_path: &Path, cache_base: &Path) -> Result<Self> {
        if !component_path.exists() {
            bail!("component not found: {}", component_path.display());
        }
        let mut config = Config::new();
        config.wasm_component_model(true);
        let engine = wasmtime::Engine::new(&config)?;
        let component = Component::from_file(&engine, component_path)
            .with_context(|| format!("load component {}", component_path.display()))?;
        std::fs::create_dir_all(cache_base)
            .with_context(|| format!("create {}", cache_base.display()))?;
        Ok(Self {
            engine,
            component,
            cache_base: cache_base.to_path_buf(),
        })
    }

    /// Runs `evaluate` and returns the parsed claims JSON. A verification failure is
    /// reported by the component inside the JSON (`{"status":"failed","error":...}`),
    /// not as an `Err` here.
    fn evaluate(&self, evaluation: &Evaluation) -> Result<Value> {
        let cache_dir = unique_cache_dir(&self.cache_base)?;

        let evidence_json = serde_json::json!({
            "quote": base64::engine::general_purpose::STANDARD.encode(&evaluation.quote),
        });
        let evidence_bytes =
            serde_json::to_vec(&evidence_json).context("serialize evidence JSON")?;

        let expected_report_data = match &evaluation.expected_report_data {
            Some(v) => iface::OptionalData::Value(v.clone()),
            None => iface::OptionalData::NotProvided,
        };
        let expected_init_data_hash = match &evaluation.expected_init_data_hash {
            Some(v) => iface::OptionalData::Value(v.clone()),
            None => iface::OptionalData::NotProvided,
        };

        let mut linker = Linker::<HostState>::new(&self.engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
        wasmtime_wasi_http::add_only_http_to_linker_sync(&mut linker)?;

        let state = HostState::new(&cache_dir)?;
        let mut store = Store::new(&self.engine, state);

        let bindings = Verifier::instantiate(&mut store, &self.component, &linker)?;
        let verifier_iface = bindings.trustee_verifier_verifier_interface();
        let verifier = verifier_iface.verifier();
        let verifier_resource = verifier.call_constructor(&mut store)?;
        let endorsements = evaluation
            .collateral
            .clone()
            .map(|payload| {
                vec![iface::Endorsement {
                    label: "sgx-collateral".to_string(),
                    media_type: SGX_COLLATERAL_MEDIA_TYPE.to_string(),
                    payload,
                }]
            })
            .unwrap_or_default();
        let evidence_media_type = infer_media_type(&evidence_bytes).to_string();
        let verifier_input = iface::VerifierInput {
            evidence: evidence_bytes,
            evidence_media_type,
            endorsements,
        };
        let out = verifier.call_evaluate(
            &mut store,
            verifier_resource,
            &verifier_input,
            &expected_report_data,
            &expected_init_data_hash,
        )?;

        serde_json::from_str(&out).context("component returned non-JSON string")
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let quote =
        std::fs::read(&args.quote).with_context(|| format!("read {}", args.quote.display()))?;
    let collateral = match &args.collateral {
        Some(path) => {
            Some(std::fs::read(path).with_context(|| format!("read {}", path.display()))?)
        }
        None => None,
    };

    let evaluation = Evaluation {
        quote,
        collateral,
        expected_report_data: args
            .expected_report_data_hex
            .as_deref()
            .map(decode_hex)
            .transpose()?,
        expected_init_data_hash: args
            .expected_init_data_hash_hex
            .as_deref()
            .map(decode_hex)
            .transpose()?,
    };

    let runner = Runner::new(&args.component, &args.cache_dir)?;
    let value = runner.evaluate(&evaluation)?;

    if let Some(err) = value.get("error") {
        eprintln!("{value}");
        return Err(anyhow!("attestation failed: {err}"));
    }

    println!("{value}");
    Ok(())
}

struct HostState {
    table: ResourceTable,
    wasi: WasiCtx,
    http: wasmtime_wasi_http::WasiHttpCtx,
}

impl HostState {
    fn new(cache_dir: &Path) -> Result<Self> {
        let mut wasi = WasiCtxBuilder::new();
        wasi.inherit_stdio();

        use wasmtime_wasi::{DirPerms, FilePerms};
        wasi.preopened_dir(cache_dir, "cache", DirPerms::all(), FilePerms::all())
            .with_context(|| format!("preopen {}", cache_dir.display()))?;

        Ok(Self {
            table: ResourceTable::new(),
            wasi: wasi.build(),
            http: wasmtime_wasi_http::WasiHttpCtx::new(),
        })
    }
}

impl IoView for HostState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
}

impl WasiView for HostState {
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
}

impl wasmtime_wasi_http::WasiHttpView for HostState {
    fn ctx(&mut self) -> &mut wasmtime_wasi_http::WasiHttpCtx {
        &mut self.http
    }
}

// ---------------------------------------------------------------------------
// Tests against the committed fixture quote
// (`sgx-verifier/test_data/sgx_dcap_v3_quote_not_debug.bin`): a real Intel SGX
// DCAP quote, ECDSA-P256 attested, captured from an enclave launched **without**
// the DEBUG attribute — so the measurements in it are meaningful, unlike those of
// a debug enclave whose memory the owner can inspect.
//
// The first test is hermetic (no network, no wasm). The component tests are
// `#[ignore]`d because they need the built component plus outbound network to
// Intel PCS for DCAP collateral:
//
//   cargo build -p sgx-verifier-component --release --target wasm32-wasip2
//   cargo test -p sgx-verifier-test -- --ignored
// ---------------------------------------------------------------------------
#[cfg(test)]
mod fixture_quote {
    use super::*;
    use serde_json::json;

    /// The enclave measurement in the fixture.
    const MR_ENCLAVE: &str = "1a818f25391de5c4939ff933175153ade954b3e31ce0b454829086c7b7f68956";
    /// The enclave signer measurement in the fixture.
    const MR_SIGNER: &str = "669b80648c2d9c97f32263fa1961f95f83818682d6359758221f0e7acb9584c0";
    /// Both REPORT_DATA and CONFIGID are unused (all-zero) in this fixture.
    const ZERO_64: &str = "0000000000000000000000000000000000000000000000000000000000000000\
                           0000000000000000000000000000000000000000000000000000000000000000";

    // SGX quote v3: 48-byte header + 384-byte report body + u32 signature length,
    // i.e. the 436 bytes the component parses before the signature blob.
    const HEADER_LEN: usize = 48;
    const BODY_LEN: usize = 384;
    const QUOTE_SIZE: usize = HEADER_LEN + BODY_LEN + 4;

    // Offsets within the report body (see sgx-verifier-component/src/types.rs).
    const ATTRIBUTES_FLAGS: usize = 48;
    const MR_ENCLAVE_OFFSET: usize = 64;
    const MR_SIGNER_OFFSET: usize = 128;
    const CONFIG_ID_OFFSET: usize = 192;
    const REPORT_DATA_OFFSET: usize = 320;

    // SGX enclave attribute bits.
    const SGX_FLAGS_INITTED: u64 = 0x01;
    const SGX_FLAGS_DEBUG: u64 = 0x02;
    const SGX_FLAGS_MODE64BIT: u64 = 0x04;

    // ECDSA-256-with-P-256 curve, the only attestation key type DCAP quotes use.
    const ATT_KEY_TYPE_ECDSA_P256: u16 = 2;

    fn manifest_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn quote() -> Vec<u8> {
        let path = manifest_dir().join("../test_data/sgx_dcap_v3_quote_not_debug.bin");
        std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    fn runner() -> Runner {
        let component =
            manifest_dir().join("../../target/wasm32-wasip2/release/sgx_verifier_component.wasm");
        assert!(
            component.exists(),
            "component missing: {} — build it with \
             `cargo build -p sgx-verifier-component --release --target wasm32-wasip2`",
            component.display()
        );
        Runner::new(
            &component,
            &manifest_dir().join("../../.sgx-verifier-cache"),
        )
        .expect("load component")
    }

    fn evaluation() -> Evaluation {
        Evaluation {
            quote: quote(),
            ..Default::default()
        }
    }

    /// Hermetic: the committed fixture is the quote it claims to be — a v3 ECDSA
    /// DCAP quote over a production (non-debug) enclave with the recorded
    /// measurements. Guards against the fixture being swapped or truncated.
    #[test]
    fn fixture_is_a_non_debug_ecdsa_quote() {
        let quote = quote();
        assert!(
            quote.len() >= QUOTE_SIZE,
            "quote too short: {} bytes",
            quote.len()
        );
        assert_eq!(
            u16::from_le_bytes([quote[0], quote[1]]),
            3,
            "expected SGX quote version 3"
        );
        assert_eq!(
            u16::from_le_bytes([quote[2], quote[3]]),
            ATT_KEY_TYPE_ECDSA_P256,
            "expected an ECDSA-P256 attestation key"
        );

        // The signature blob following the parsed prefix accounts for the rest of
        // the file, so this is a whole quote and not a clipped one.
        let signature_data_len =
            u32::from_le_bytes(quote[QUOTE_SIZE - 4..QUOTE_SIZE].try_into().unwrap()) as usize;
        assert_eq!(
            quote.len(),
            QUOTE_SIZE + signature_data_len,
            "signature_data_len ({signature_data_len}) does not account for the file tail"
        );

        let body = &quote[HEADER_LEN..HEADER_LEN + BODY_LEN];
        let flags = u64::from_le_bytes(
            body[ATTRIBUTES_FLAGS..ATTRIBUTES_FLAGS + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            flags & SGX_FLAGS_DEBUG,
            0,
            "fixture is a DEBUG enclave (flags {flags:#x}); its measurements are not trustworthy"
        );
        assert_eq!(
            flags,
            SGX_FLAGS_INITTED | SGX_FLAGS_MODE64BIT,
            "unexpected enclave attributes: {flags:#x}"
        );

        assert_eq!(
            hex::encode(&body[MR_ENCLAVE_OFFSET..MR_ENCLAVE_OFFSET + 32]),
            MR_ENCLAVE,
            "MRENCLAVE drifted from the captured quote"
        );
        assert_eq!(
            hex::encode(&body[MR_SIGNER_OFFSET..MR_SIGNER_OFFSET + 32]),
            MR_SIGNER,
            "MRSIGNER drifted from the captured quote"
        );
        assert_eq!(
            hex::encode(&body[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + 64]),
            ZERO_64,
            "fixture REPORT_DATA is no longer all-zero"
        );
        assert_eq!(
            hex::encode(&body[CONFIG_ID_OFFSET..CONFIG_ID_OFFSET + 64]),
            ZERO_64,
            "fixture CONFIGID is no longer all-zero"
        );
    }

    /// End-to-end through the Wasm component: the fixture verifies against
    /// collateral fetched from Intel PCS and yields the expected claims.
    #[test]
    #[ignore = "requires sgx_verifier_component.wasm + Intel PCS network"]
    fn component_accepts_fixture_quote() {
        let claims = runner()
            .evaluate(&evaluation())
            .expect("evaluate fixture quote");
        assert!(
            claims.get("error").is_none(),
            "verification failed: {claims}"
        );

        assert_eq!(claims["tee_type"], json!("sgx"));
        assert_eq!(claims["header"]["version"], json!("0300"));
        assert_eq!(claims["body"]["mr_enclave"], json!(MR_ENCLAVE));
        assert_eq!(claims["body"]["mr_signer"], json!(MR_SIGNER));
        // DEBUG bit clear, as asserted offline above.
        assert_eq!(
            claims["body"]["attributes.flags"],
            json!("0500000000000000")
        );
        assert_eq!(claims["report_data"], json!(ZERO_64));
        assert_eq!(claims["init_data"], json!(ZERO_64));

        // TCB claims come from the freshly fetched collateral, so the exact values
        // move as Intel publishes TCB updates (this platform reports
        // `OutOfDateConfigurationNeeded` with a non-empty advisory list).
        assert!(
            claims["tcb_status"].as_str().is_some_and(|s| !s.is_empty()),
            "missing tcb_status claim: {claims}"
        );
        assert!(
            claims["advisory_ids"].is_array(),
            "missing advisory_ids claim: {claims}"
        );
        assert!(
            claims["platform_provider_id"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "missing platform_provider_id claim: {claims}"
        );
    }

    /// The REPORT_DATA / CONFIGID bindings are enforced: the fixture's zero values
    /// are accepted, and anything else fails closed.
    #[test]
    #[ignore = "requires sgx_verifier_component.wasm + Intel PCS network"]
    fn component_enforces_report_data_binding() {
        let runner = runner();

        let claims = runner
            .evaluate(&Evaluation {
                expected_report_data: Some(vec![0u8; 64]),
                expected_init_data_hash: Some(vec![0u8; 64]),
                ..evaluation()
            })
            .expect("evaluate with matching bindings");
        assert!(
            claims.get("error").is_none(),
            "matching bindings were rejected: {claims}"
        );

        let claims = runner
            .evaluate(&Evaluation {
                expected_report_data: Some(vec![0xaa; 32]),
                ..evaluation()
            })
            .expect("evaluate with mismatching REPORT_DATA");
        let error = claims["error"].as_str().unwrap_or_default();
        assert!(
            error.contains("REPORT_DATA"),
            "expected a REPORT_DATA mismatch, got: {claims}"
        );
    }
}
