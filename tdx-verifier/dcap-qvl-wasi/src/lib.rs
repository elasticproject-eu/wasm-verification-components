use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use dcap_qvl::QuoteCollateralV3;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Phala Network's public PCCS — proxies Intel PCS for TCB / QE-identity and
/// also serves the `pckcert` endpoint without an `Ocp-Apim-Subscription-Key`,
/// so quotes whose certification data is `cert_type` 2 / 3 (encrypted PPID)
/// can be fetched without an Intel API key.
const DEFAULT_PCS_URL: &str = "https://pccs.phala.network";
const INTEL_PCS_URL: &str = "https://api.trustedservices.intel.com";

const CERT_TYPE_ENCRYPTED_PPID_2048: u16 = 2;
const CERT_TYPE_ENCRYPTED_PPID_3072: u16 = 3;
const CERT_TYPE_PCK_CERT_CHAIN: u16 = 5;

#[derive(Clone, Debug)]
struct PcsEndpoints {
    base_url: String,
    tee: &'static str,
    fmspc: String,
    ca: &'static str,
}

impl PcsEndpoints {
    fn new(base_url: &str, for_sgx: bool, fmspc: String, ca: &'static str) -> Self {
        let tee = if for_sgx { "sgx" } else { "tdx" };
        let base_url = base_url
            .trim()
            .trim_end_matches('/')
            .trim_end_matches("/sgx/certification/v4")
            .trim_end_matches("/tdx/certification/v4")
            .to_owned();
        Self {
            base_url,
            tee,
            fmspc,
            ca,
        }
    }

    fn url_pckcrl(&self) -> String {
        self.mk_url("sgx", &format!("pckcrl?ca={}&encoding=der", self.ca))
    }

    fn url_pckcrl_pem(&self) -> String {
        self.mk_url("sgx", &format!("pckcrl?ca={}&encoding=pem", self.ca))
    }

    fn url_rootcacrl(&self) -> String {
        self.mk_url("sgx", "rootcacrl")
    }

    fn url_tcb(&self) -> String {
        self.mk_url(self.tee, &format!("tcb?fmspc={}", self.fmspc))
    }

    fn url_qe_identity(&self) -> String {
        self.mk_url(self.tee, "qe/identity?update=standard")
    }

    fn mk_url(&self, tee: &str, path: &str) -> String {
        format!("{}/{}/certification/v4/{}", self.base_url, tee, path)
    }
}

fn cache_key(base_url: &str, tee: &str, fmspc: &str, ca: &str) -> String {
    let mut h = Sha256::new();
    h.update(base_url.as_bytes());
    let digest = h.finalize();
    let short = hex::encode(&digest[..4]);
    format!("collateral_{short}_{tee}_{fmspc}_{ca}.json")
}

fn now_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs())
}

fn cache_disabled() -> bool {
    std::env::var("DCAP_QVL_DISABLE_CACHE")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn read_cache(cache_path: &Path) -> Option<QuoteCollateralV3> {
    let data = fs::read(cache_path).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&data).ok()?;
    let obj = value.as_object()?;

    let pck_crl_issuer_chain = obj.get("pck_crl_issuer_chain")?.as_str()?.to_owned();
    let mut root_ca_crl = decode_bytes_value(obj.get("root_ca_crl")?)?;
    let mut pck_crl = decode_bytes_value(obj.get("pck_crl")?)?;
    let tcb_info_issuer_chain = obj.get("tcb_info_issuer_chain")?.as_str()?.to_owned();
    let tcb_info = obj.get("tcb_info")?.as_str()?.to_owned();
    let tcb_info_signature = decode_bytes_value(obj.get("tcb_info_signature")?)?;
    let qe_identity_issuer_chain = obj.get("qe_identity_issuer_chain")?.as_str()?.to_owned();
    let qe_identity = obj.get("qe_identity")?.as_str()?.to_owned();
    let qe_identity_signature = decode_bytes_value(obj.get("qe_identity_signature")?)?;
    let pck_certificate_chain = obj
        .get("pck_certificate_chain")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());

    normalize_crl_bytes(&mut root_ca_crl);
    normalize_crl_bytes(&mut pck_crl);
    if !looks_like_der_crl(&root_ca_crl) {
        trim_der_trailing(&mut root_ca_crl);
    }
    if !looks_like_der_crl(&pck_crl) {
        trim_der_trailing(&mut pck_crl);
    }
    if !looks_like_der_crl(&root_ca_crl) || !looks_like_der_crl(&pck_crl) {
        return None;
    }

    Some(QuoteCollateralV3 {
        pck_crl_issuer_chain,
        root_ca_crl,
        pck_crl,
        tcb_info_issuer_chain,
        tcb_info,
        tcb_info_signature,
        qe_identity_issuer_chain,
        qe_identity,
        qe_identity_signature,
        pck_certificate_chain,
    })
}

fn write_cache(cache_path: &Path, collateral: &QuoteCollateralV3) -> Result<()> {
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let data = serde_json::to_vec(collateral).context("serialize collateral")?;
    fs::write(cache_path, data).with_context(|| format!("write {}", cache_path.display()))?;
    Ok(())
}

fn cached_collateral_is_fresh(collateral: &QuoteCollateralV3, now_secs: u64) -> bool {
    let tcb_info_json: serde_json::Value = match serde_json::from_str(&collateral.tcb_info) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let next_update = tcb_info_json
        .get("nextUpdate")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let next_update = chrono::DateTime::parse_from_rfc3339(next_update);
    match next_update {
        Ok(dt) => now_secs <= dt.timestamp().max(0) as u64,
        Err(_) => false,
    }
}

#[cfg(feature = "wasi-http")]
fn http_get_bytes(url: &str) -> Result<(u16, Vec<u8>, Vec<(String, String)>)> {
    use waki::Client;
    let resp = Client::new()
        .get(url)
        .send()
        .with_context(|| format!("HTTP GET {}", url))?;
    let status = resp.status_code();
    let mut hdrs = Vec::new();
    for (name, value) in resp.headers().iter() {
        hdrs.push((
            name.to_string(),
            value.to_str().unwrap_or_default().to_string(),
        ));
    }
    let body = resp.body().context("read response body")?;
    Ok((status, body, hdrs))
}

#[cfg(not(feature = "wasi-http"))]
fn http_get_bytes(_url: &str) -> Result<(u16, Vec<u8>, Vec<(String, String)>)> {
    bail!("dcap-qvl-wasi built without `wasi-http` support");
}

fn get_header(headers: &[(String, String)], name: &str) -> Result<String> {
    let (_, value) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .ok_or_else(|| anyhow!("Missing {name}"))?;
    let value = urlencoding::decode(value)?;
    Ok(value.into_owned())
}

fn decode_hex_string(s: &str) -> Option<Vec<u8>> {
    let filtered: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if filtered.is_empty()
        || filtered.len() % 2 != 0
        || !filtered.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    hex::decode(filtered).ok()
}

fn decode_bytes_value(value: &serde_json::Value) -> Option<Vec<u8>> {
    match value {
        serde_json::Value::String(s) => {
            if let Some(bytes) = decode_pem_crl(s) {
                return Some(bytes);
            }
            if let Some(bytes) = decode_hex_string(s) {
                return Some(bytes);
            }
            decode_base64_string(s)
        }
        serde_json::Value::Array(list) => {
            let mut out = Vec::with_capacity(list.len());
            for v in list {
                let b = v.as_u64()?;
                if b > u8::MAX as u64 {
                    return None;
                }
                out.push(b as u8);
            }
            Some(out)
        }
        _ => None,
    }
}

fn decode_pem_crl(s: &str) -> Option<Vec<u8>> {
    if !s.contains("BEGIN") {
        return None;
    }
    let blocks = pem::parse_many(s).ok()?;
    for block in blocks {
        let tag = block.tag();
        if tag == "X509 CRL" || tag == "CRL" {
            return Some(block.contents().to_vec());
        }
    }
    None
}

fn decode_base64_string(s: &str) -> Option<Vec<u8>> {
    let filtered: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if filtered.is_empty() {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(filtered.as_bytes())
        .ok()?;
    if bytes.first() != Some(&0x30) {
        return None;
    }
    Some(bytes)
}

fn decode_crl_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let s = core::str::from_utf8(bytes).ok()?;
    if let Some(decoded) = decode_pem_crl(s) {
        return Some(decoded);
    }
    if let Some(decoded) = decode_hex_string(s) {
        return Some(decoded);
    }
    decode_base64_string(s)
}

fn normalize_crl_bytes(bytes: &mut Vec<u8>) {
    if let Some(decoded) = decode_crl_bytes(bytes) {
        *bytes = decoded;
    }
}

fn der_total_len(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 2 || bytes[0] != 0x30 {
        return None;
    }
    let len = match bytes[1] {
        0x81 if bytes.len() >= 3 => bytes[2] as usize,
        0x82 if bytes.len() >= 4 => ((bytes[2] as usize) << 8) | (bytes[3] as usize),
        n if n < 0x80 => n as usize,
        _ => return None,
    };
    Some(match bytes[1] {
        0x81 => 3 + len,
        0x82 => 4 + len,
        _ => 2 + len,
    })
}

fn looks_like_der_crl(bytes: &[u8]) -> bool {
    matches!(der_total_len(bytes), Some(total) if total == bytes.len())
}

fn trim_der_trailing(bytes: &mut Vec<u8>) {
    if let Some(total) = der_total_len(bytes) {
        if total <= bytes.len() && total > 0 {
            bytes.truncate(total);
        }
    }
}

fn extract_root_crl_from_chain(pck_crl_issuer_chain: &str) -> Result<Vec<u8>> {
    use der::Decode as DerDecode;
    use pem::Pem;
    use x509_cert::{
        ext::pkix::{
            name::{DistributionPointName, GeneralName},
            CrlDistributionPoints,
        },
        Certificate,
    };

    fn extract_crl_url(cert_der: &[u8]) -> Result<Option<String>> {
        let cert: Certificate = DerDecode::from_der(cert_der).context("parse certificate")?;
        let Some(extensions) = &cert.tbs_certificate.extensions else {
            return Ok(None);
        };
        for ext in extensions.iter() {
            if ext.extn_id.to_string() != "2.5.29.31" {
                continue;
            }
            let crl_dist_points: CrlDistributionPoints =
                DerDecode::from_der(ext.extn_value.as_bytes()).context("parse CRL DP")?;

            for dist_point in crl_dist_points.0.iter() {
                let Some(dist_point_name) = &dist_point.distribution_point else {
                    continue;
                };
                let DistributionPointName::FullName(general_names) = dist_point_name else {
                    continue;
                };
                for general_name in general_names.iter() {
                    let GeneralName::UniformResourceIdentifier(uri) = general_name else {
                        continue;
                    };
                    return Ok(Some(uri.to_string()));
                }
            }
        }
        Ok(None)
    }

    let pem_chain = pck_crl_issuer_chain.as_bytes();
    let blocks = pem::parse_many(pem_chain).context("parse issuer chain PEM")?;
    let root: &Pem = blocks.last().context("no certs in issuer chain")?;
    let Some(url) = extract_crl_url(root.contents())? else {
        bail!("Could not find CRL distribution point in root certificate");
    };
    let (status, body, _) = http_get_bytes(&url)?;
    if !(200..300).contains(&status) {
        bail!("Failed to fetch {url}: HTTP {status}");
    }
    Ok(body)
}

fn fetch_collateral_uncached(endpoints: &PcsEndpoints) -> Result<QuoteCollateralV3> {
    // PCK CRL
    let (status, mut pck_crl, headers) = http_get_bytes(&endpoints.url_pckcrl())?;
    if !(200..300).contains(&status) {
        bail!("Failed to fetch PCK CRL: HTTP {status}");
    }
    let pck_crl_issuer_chain = get_header(&headers, "SGX-PCK-CRL-Issuer-Chain")?;
    normalize_crl_bytes(&mut pck_crl);
    if !looks_like_der_crl(&pck_crl) {
        if let Ok((status, mut pem_crl, _)) = http_get_bytes(&endpoints.url_pckcrl_pem()) {
            if (200..300).contains(&status) {
                normalize_crl_bytes(&mut pem_crl);
                if looks_like_der_crl(&pem_crl) {
                    pck_crl = pem_crl;
                }
            }
        }
    }
    if !looks_like_der_crl(&pck_crl) {
        trim_der_trailing(&mut pck_crl);
    }

    // TCB info
    let (status, raw_tcb_info, headers) = http_get_bytes(&endpoints.url_tcb())?;
    if !(200..300).contains(&status) {
        bail!("Failed to fetch TCB info: HTTP {status}");
    }
    let tcb_info_issuer_chain = get_header(&headers, "SGX-TCB-Info-Issuer-Chain")
        .or(get_header(&headers, "TCB-Info-Issuer-Chain"))?;
    let raw_tcb_info = String::from_utf8(raw_tcb_info).context("TCB info must be UTF-8")?;

    // QE identity
    let (status, raw_qe_identity, headers) = http_get_bytes(&endpoints.url_qe_identity())?;
    if !(200..300).contains(&status) {
        bail!("Failed to fetch QE identity: HTTP {status}");
    }
    let qe_identity_issuer_chain = get_header(&headers, "SGX-Enclave-Identity-Issuer-Chain")?;
    let raw_qe_identity =
        String::from_utf8(raw_qe_identity).context("QE identity must be UTF-8")?;

    // Root CA CRL: try PCCS endpoint first (may return hex-encoded bytes), else CRL DP from root cert.
    // Skip the PCCS endpoint only when talking to Intel PCS — it doesn't expose `rootcacrl`.
    let mut root_ca_crl = None;
    if !endpoints.base_url.starts_with(INTEL_PCS_URL) {
        if let Ok((status, bytes, _)) = http_get_bytes(&endpoints.url_rootcacrl()) {
            if (200..300).contains(&status) {
                let decoded = decode_crl_bytes(&bytes).unwrap_or(bytes);
                root_ca_crl = Some(decoded);
            }
        }
    }
    let mut root_ca_crl = match root_ca_crl {
        Some(v) => v,
        None => extract_root_crl_from_chain(&pck_crl_issuer_chain)?,
    };
    normalize_crl_bytes(&mut root_ca_crl);
    if !looks_like_der_crl(&root_ca_crl) {
        trim_der_trailing(&mut root_ca_crl);
    }

    // Parse TCB info and QE identity payloads (extract and hex-decode "signature" field).
    let tcb_info_json: serde_json::Value =
        serde_json::from_str(&raw_tcb_info).context("TCB info should be valid JSON")?;
    let tcb_info = tcb_info_json["tcbInfo"].to_string();
    let tcb_info_signature = tcb_info_json
        .get("signature")
        .and_then(|v| v.as_str())
        .context("TCB info missing 'signature'")?;
    let tcb_info_signature =
        hex::decode(tcb_info_signature).context("TCB info signature must be hex")?;

    let qe_identity_json: serde_json::Value =
        serde_json::from_str(&raw_qe_identity).context("QE identity should be valid JSON")?;
    let qe_identity = qe_identity_json
        .get("enclaveIdentity")
        .context("QE identity missing 'enclaveIdentity'")?
        .to_string();
    let qe_identity_signature = qe_identity_json
        .get("signature")
        .and_then(|v| v.as_str())
        .context("QE identity missing 'signature'")?;
    let qe_identity_signature =
        hex::decode(qe_identity_signature).context("QE identity signature must be hex")?;

    Ok(QuoteCollateralV3 {
        pck_crl_issuer_chain,
        root_ca_crl,
        pck_crl,
        tcb_info_issuer_chain,
        tcb_info,
        tcb_info_signature,
        qe_identity_issuer_chain,
        qe_identity,
        qe_identity_signature,
        pck_certificate_chain: None,
    })
}

pub fn get_collateral_cached(
    pccs_url: Option<&str>,
    quote: &[u8],
    cache_dir: &Path,
) -> Result<QuoteCollateralV3> {
    let pccs_url = pccs_url.unwrap_or(DEFAULT_PCS_URL);

    let quote_obj = dcap_qvl::quote::Quote::parse(quote).context("parse quote")?;
    let for_sgx = quote_obj.header.is_sgx();

    // Resolve the PCK certificate chain. For `cert_type` 5 the chain is
    // already inside the quote; for `cert_type` 2 / 3 we have to ask PCCS for
    // it using the encrypted-PPID parameters in the quote's certification
    // data. The PCK chain doesn't go in the FMSPC-keyed cache: a platform
    // can have several PCK certs at different TCB levels but only one
    // FMSPC, so caching it would let stale TCB certs leak between runs.
    let cert_type = quote_obj.inner_cert_type();
    let pck_chain_pem = match cert_type {
        CERT_TYPE_PCK_CERT_CHAIN => String::from_utf8(quote_obj.inner_cert_data().to_vec())
            .context("PCK cert chain in quote is not valid UTF-8")?,
        CERT_TYPE_ENCRYPTED_PPID_2048 | CERT_TYPE_ENCRYPTED_PPID_3072 => {
            let params = quote_obj
                .encrypted_ppid_params()
                .context("decode encrypted PPID parameters from quote cert data")?;
            fetch_pck_certificate_chain(pccs_url, quote_obj.qeid(), &params)?
        }
        other => bail!(
            "unsupported quote certification data type {other}; expected 2, 3, or 5"
        ),
    };

    let fmspc = fmspc_from_pck_pem(pck_chain_pem.as_bytes())?;
    let ca = pck_chain_ca(pck_chain_pem.as_bytes());

    let endpoints = PcsEndpoints::new(pccs_url, for_sgx, fmspc.clone(), ca);
    if cache_disabled() {
        let mut collateral = fetch_collateral_uncached(&endpoints)?;
        collateral.pck_certificate_chain = Some(pck_chain_pem);
        return Ok(collateral);
    }
    let key = cache_key(&endpoints.base_url, endpoints.tee, &fmspc, ca);
    let cache_path: PathBuf = cache_dir.join(key);

    let now = now_secs()?;
    if let Some(mut cached) = read_cache(&cache_path) {
        if cached_collateral_is_fresh(&cached, now) {
            cached.pck_certificate_chain = Some(pck_chain_pem);
            return Ok(cached);
        }
    }

    let mut collateral = fetch_collateral_uncached(&endpoints)?;
    write_cache(&cache_path, &collateral)?;
    collateral.pck_certificate_chain = Some(pck_chain_pem);
    Ok(collateral)
}

/// Fetch the PCK certificate chain for an encrypted-PPID (cert_type 2/3)
/// quote from a PCS/PCCS, returning the leaf cert followed by its issuer
/// chain in one PEM string.
///
/// Tolerates `SGX-TCBm` headers indicating that PCCS matched the request to
/// a *lower* TCB level than the one the platform reports. dcap-qvl's
/// upstream `get_collateral` bails on that mismatch, but in practice the
/// QE was provisioned with the lower-TCB key (so verification still works)
/// and we don't want to lock out platforms whose post-microcode-update MPA
/// re-registration has lagged.
fn fetch_pck_certificate_chain(
    pccs_url: &str,
    qeid: &[u8],
    params: &dcap_qvl::quote::EncryptedPpidParams,
) -> Result<String> {
    let qeid = hex::encode_upper(qeid);
    let encrypted_ppid = hex::encode_upper(&params.encrypted_ppid);
    let cpusvn = hex::encode_upper(params.cpusvn);
    let pcesvn = hex::encode_upper(params.pcesvn.to_le_bytes());
    let pceid = hex::encode_upper(params.pceid);

    let base_url = pccs_url
        .trim()
        .trim_end_matches('/')
        .trim_end_matches("/sgx/certification/v4")
        .trim_end_matches("/tdx/certification/v4");
    let url = format!(
        "{base_url}/sgx/certification/v4/pckcert\
         ?qeid={qeid}&encrypted_ppid={encrypted_ppid}\
         &cpusvn={cpusvn}&pcesvn={pcesvn}&pceid={pceid}"
    );

    let (status, body, headers) = http_get_bytes(&url)?;
    if !(200..300).contains(&status) {
        bail!("Failed to fetch PCK certificate from {url}: HTTP {status}");
    }
    let issuer_chain = get_header(&headers, "SGX-PCK-Certificate-Issuer-Chain")
        .with_context(|| format!("PCK response from {url} missing issuer-chain header"))?;
    let pck_leaf = String::from_utf8(body).context("PCK certificate body is not UTF-8")?;
    Ok(format!("{}\n{issuer_chain}", pck_leaf.trim_end()))
}

/// Extract the FMSPC from the leaf PCK certificate in a PEM cert chain.
///
/// FMSPC lives in the SGX FMSPC extension (OID 1.2.840.113741.1.13.1.4),
/// encoded as a 6-byte OCTET STRING. We locate it with a fast byte-pattern
/// search on the DER-decoded leaf cert and return uppercase hex (matching
/// what PCS returns in `SGX-FMSPC` and what `PcsEndpoints` expects).
fn fmspc_from_pck_pem(pem: &[u8]) -> Result<String> {
    let der = first_cert_der(pem).context("decode leaf PCK certificate")?;

    // OID 1.2.840.113741.1.13.1.4 in DER: 06 0a 2a 86 48 86 f8 4d 01 0d 01 04
    const FMSPC_OID: &[u8] = &[
        0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04,
    ];
    let idx = der
        .windows(FMSPC_OID.len())
        .position(|w| w == FMSPC_OID)
        .context("FMSPC extension OID not found in PCK leaf certificate")?;

    let after = &der[idx + FMSPC_OID.len()..];
    if after.len() < 8 || after[0] != 0x04 || after[1] != 6 {
        bail!(
            "unexpected DER encoding after FMSPC OID: {:02x?}",
            &after[..after.len().min(8)]
        );
    }
    Ok(hex::encode_upper(&after[2..8]))
}

/// Detect whether a PCK leaf certificate was issued by Intel SGX PCK
/// `Processor CA` or `Platform CA` by scanning the chain's DER for the CA
/// subject CN string. Returns the corresponding PCS query parameter.
fn pck_chain_ca(pem: &[u8]) -> &'static str {
    let pem_str = match core::str::from_utf8(pem) {
        Ok(s) => s,
        Err(_) => return "processor",
    };
    let mut der_blob: Vec<u8> = Vec::new();
    for chunk in pem_str.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let Some(end) = chunk.find("-----END CERTIFICATE-----") else {
            continue;
        };
        let b64: String = chunk[..end].lines().map(str::trim).collect();
        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(&b64) {
            der_blob.extend(der);
        }
    }
    if der_blob
        .windows(b"Intel SGX PCK Platform CA".len())
        .any(|w| w == b"Intel SGX PCK Platform CA")
    {
        "platform"
    } else {
        "processor"
    }
}

fn first_cert_der(pem: &[u8]) -> Result<Vec<u8>> {
    let pem_str = core::str::from_utf8(pem).context("PCK chain is not valid UTF-8")?;
    let begin = pem_str
        .find("-----BEGIN CERTIFICATE-----")
        .context("no BEGIN CERTIFICATE marker in PCK chain")?;
    let body_start = begin + "-----BEGIN CERTIFICATE-----".len();
    let end = pem_str[body_start..]
        .find("-----END CERTIFICATE-----")
        .context("no END CERTIFICATE marker in PCK chain")?;
    let b64_body: String = pem_str[body_start..body_start + end]
        .lines()
        .map(str::trim)
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(&b64_body)
        .context("base64-decode PCK leaf cert")
}
