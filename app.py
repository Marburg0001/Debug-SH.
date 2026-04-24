import os
from flask import Flask, render_template, request, jsonify
import ipaddress
import random
import socket
import string
import time
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

REQUEST_HEADERS = {"User-Agent": USER_AGENT}
VERIFY_META_NAME = "debugish-verification"
VERIFY_TXT_FILE = "debugish-verification.txt"

verification_store = {}
verified_domains = set()


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def get_domain_key(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    return parsed.netloc.lower().replace("www.", "")


def generate_verification_code(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def is_private_or_local_host(hostname: str) -> bool:
    hostname = (hostname or "").strip().lower()
    if not hostname:
        return True

    blocked_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
    if hostname in blocked_hosts:
        return True

    try:
        socket.inet_aton(hostname)
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    except Exception:
        pass

    return False


def add_issue(issues, category, severity, title, why, fix_code, details=None):
    issues.append({
        "category": category,
        "severity": severity,
        "title": title,
        "why": why,
        "details": details or "",
        "fix_code": fix_code,
    })


def fetch_url(url: str, timeout: int = 10):
    return requests.get(
        url,
        timeout=timeout,
        headers=REQUEST_HEADERS,
        allow_redirects=True
    )


def check_resource(url: str, timeout: int = 6):
    try:
        response = fetch_url(url, timeout=timeout)
        return response.status_code, response
    except Exception:
        return None, None


def safe_text(value, fallback="-"):
    if value is None:
        return fallback
    value = str(value).strip()
    return value if value else fallback


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/generate-code", methods=["POST"])
def generate_code():
    data = request.get_json(silent=True) or {}
    raw_url = (data.get("url") or "").strip()

    if not raw_url:
        return jsonify({"error": "URL boş olamaz."}), 400

    normalized_url = normalize_url(raw_url)
    parsed = urlparse(normalized_url)

    if not parsed.netloc:
        return jsonify({"error": "Geçerli domain gir"}), 400

    if is_private_or_local_host(parsed.hostname):
        return jsonify({"error": "Local/private adres yasak"}), 400

    domain_key = get_domain_key(normalized_url)
    code = generate_verification_code()

    verification_store[domain_key] = {
        "code": code,
        "url": normalized_url,
        "domain": domain_key,
        "created_at": int(time.time())
    }

    return jsonify({
        "domain": domain_key,
        "url": normalized_url,
        "code": code,
        "meta_tag": f'<meta name="{VERIFY_META_NAME}" content="{code}" />',
        "txt_filename": VERIFY_TXT_FILE,
        "txt_content": code
    })


@app.route("/verify-domain", methods=["POST"])
def verify_domain():
    data = request.get_json(silent=True) or {}
    raw_url = (data.get("url") or "").strip()
    url = normalize_url(raw_url)

    if not url:
        return jsonify({"error": "URL gerekli"}), 400

    domain_key = get_domain_key(url)
    verification_data = verification_store.get(domain_key)

    if not verification_data:
        return jsonify({"error": "Önce kod oluştur"}), 400

    code = verification_data["code"]

    try:
        res = fetch_url(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")

        meta = soup.find("meta", attrs={"name": VERIFY_META_NAME})
        if meta and meta.get("content") == code:
            verified_domains.add(domain_key)
            return jsonify({
                "verified": True,
                "method": "Meta Tag",
                "domain": domain_key
            })

        txt_url = urljoin(url.rstrip("/") + "/", VERIFY_TXT_FILE)
        txt_res = fetch_url(txt_url, timeout=10)
        if txt_res.status_code == 200 and txt_res.text.strip() == code:
            verified_domains.add(domain_key)
            return jsonify({
                "verified": True,
                "method": "TXT Dosyası",
                "domain": domain_key
            })

        return jsonify({"error": "Doğrulama kodu bulunamadı"}), 400

    except Exception as e:
        return jsonify({"error": f"Doğrulama hatası: {str(e)}"}), 500


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    raw_url = (data.get("url") or "").strip()
    url = normalize_url(raw_url)

    if not url:
        return jsonify({"error": "URL gerekli"}), 400

    domain_key = get_domain_key(url)

    if domain_key not in verified_domains:
        return jsonify({"error": "Doğrulanmamış domain"}), 403

    try:
        start = time.time()
        res = fetch_url(url, timeout=10)
        end = time.time()

        soup = BeautifulSoup(res.text, "html.parser")
        issues = []
        passed_checks = []
        broken_links = []

        title_tag = soup.title.string.strip() if soup.title and soup.title.string else ""
        meta_desc_tag = soup.find("meta", {"name": "description"})
        meta_desc = meta_desc_tag.get("content", "").strip() if meta_desc_tag else ""
        h1_tags = soup.find_all("h1")
        viewport_tag = soup.find("meta", {"name": "viewport"})
        canonical_tag = soup.find("link", {"rel": "canonical"})

        page_size_kb = round(len(res.content) / 1024, 2)
        response_time = round(end - start, 2)

        if title_tag:
            passed_checks.append("Title etiketi mevcut.")
        else:
            add_issue(issues, "SEO", "Kritik", "Title yok", "SEO zayıf", "<title>Başlık</title>")

        if meta_desc:
            passed_checks.append("Meta description mevcut.")
        else:
            add_issue(
                issues,
                "SEO",
                "Kritik",
                "Meta description yok",
                "Arama sonuçlarında tıklanma oranı düşebilir.",
                '<meta name="description" content="Açıklama metni" />'
            )

        if h1_tags:
            passed_checks.append("En az bir H1 etiketi mevcut.")
        else:
            add_issue(issues, "Yapı", "Kritik", "H1 yok", "Sayfa ana başlığı eksik.", "<h1>Ana Başlık</h1>")

        if viewport_tag:
            passed_checks.append("Viewport meta etiketi mevcut.")
        else:
            add_issue(
                issues,
                "Mobil",
                "Orta",
                "Viewport yok",
                "Mobil uyumluluk zayıflar.",
                '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
            )

        if canonical_tag and canonical_tag.get("href"):
            passed_checks.append("Canonical etiketi mevcut.")
        else:
            add_issue(
                issues,
                "SEO",
                "Orta",
                "Canonical yok",
                "Kopya içerik sinyali oluşabilir.",
                '<link rel="canonical" href="https://site.com/sayfa" />'
            )

        if url.startswith("https://"):
            passed_checks.append("HTTPS kullanılıyor.")
        else:
            add_issue(
                issues,
                "Güvenlik",
                "Kritik",
                "HTTPS yok",
                "Bağlantı güvenli değil.",
                "Sunucuda SSL sertifikası kur ve HTTPS yönlendirmesi ekle."
            )

        security_headers = {}
        for header in SECURITY_HEADERS:
            value = res.headers.get(header)
            security_headers[header] = value if value else "Yok"
            if value:
                passed_checks.append(f"{header} header mevcut.")
            else:
                add_issue(
                    issues,
                    "Güvenlik",
                    "Orta",
                    f"{header} eksik",
                    "Temel güvenlik korumaları zayıf kalır.",
                    f"# Sunucu yapılandırmasına {header} header ekle"
                )

        robots_url = urljoin(url.rstrip("/") + "/", "robots.txt")
        sitemap_url = urljoin(url.rstrip("/") + "/", "sitemap.xml")

        robots_status, _ = check_resource(robots_url)
        sitemap_status, _ = check_resource(sitemap_url)

        robots_exists = robots_status == 200
        sitemap_exists = sitemap_status == 200

        if robots_exists:
            passed_checks.append("robots.txt bulundu.")
        else:
            add_issue(
                issues,
                "Teknik",
                "Düşük",
                "robots.txt yok",
                "Arama motoru tarama yönlendirmesi eksik olabilir.",
                "User-agent: *\nAllow: /"
            )

        if sitemap_exists:
            passed_checks.append("sitemap.xml bulundu.")
        else:
            add_issue(
                issues,
                "SEO",
                "Düşük",
                "sitemap.xml yok",
                "Arama motorlarının sayfaları keşfetmesi zorlaşabilir.",
                '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>'
            )

        compression = res.headers.get("Content-Encoding", "Yok")
        if compression != "Yok":
            passed_checks.append("Sıkıştırma aktif.")
        else:
            add_issue(
                issues,
                "Performans",
                "Orta",
                "Sıkıştırma yok",
                "Sayfa daha yavaş yüklenebilir.",
                "# gzip veya brotli sıkıştırmasını aktif et"
            )

        images = soup.find_all("img")
        images_missing_alt = sum(1 for img in images if not (img.get("alt") or "").strip())
        if images_missing_alt == 0 and images:
            passed_checks.append("Görsellerde alt metin eksikliği tespit edilmedi.")
        elif images_missing_alt > 0:
            add_issue(
                issues,
                "SEO",
                "Düşük",
                "Alt metni eksik görseller var",
                "Erişilebilirlik ve görsel SEO zayıflar.",
                '<img src="ornek.jpg" alt="Açıklayıcı metin" />',
                f"Eksik alt metin sayısı: {images_missing_alt}"
            )

        links = soup.find_all("a", href=True)
        checked_links = 0
        for a in links[:15]:
            href = a.get("href", "").strip()
            if not href or href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:") or href.startswith("tel:"):
                continue

            full_link = urljoin(url, href)
            status_code, _ = check_resource(full_link, timeout=5)
            checked_links += 1

            if status_code and status_code >= 400:
                broken_links.append({"url": full_link, "status": status_code})

        if broken_links:
            add_issue(
                issues,
                "Teknik",
                "Orta",
                "Bozuk linkler bulundu",
                "Kullanıcı deneyimi ve crawl kalitesi düşer.",
                "Bozuk linkleri güncelle veya kaldır.",
                f"Bozuk link sayısı: {len(broken_links)}"
            )
        else:
            passed_checks.append("Kontrol edilen bağlantılarda bozuk link bulunmadı.")

        critical_count = sum(1 for i in issues if i["severity"].lower() == "kritik")
        medium_count = sum(1 for i in issues if i["severity"].lower() == "orta")
        low_count = sum(1 for i in issues if i["severity"].lower() in ["düşük", "dusuk"])

        seo_score = max(0, 100 - (critical_count * 18 + medium_count * 8 + low_count * 4))
        security_score = max(0, 100 - sum(
            15 for i in issues if i["category"] == "Güvenlik" and i["severity"] == "Kritik"
        ) - sum(
            8 for i in issues if i["category"] == "Güvenlik" and i["severity"] == "Orta"
        ))
        performance_score = max(0, 100 - (12 if compression == "Yok" else 0) - (10 if response_time > 2 else 0))
        technical_score = max(0, 100 - (len(broken_links) * 6) - (10 if not robots_exists else 0))

        overall_score = round((seo_score + security_score + performance_score + technical_score) / 4)

        if overall_score >= 85:
            summary_status = "Güçlü"
        elif overall_score >= 65:
            summary_status = "Orta"
        else:
            summary_status = "Geliştirilmeli"

        return jsonify({
            "domain": domain_key,
            "url": url,
            "status_code": res.status_code,
            "response_time": response_time,
            "summary_status": summary_status,
            "overall_score": overall_score,
            "category_scores": {
                "seo": seo_score,
                "security": security_score,
                "performance": performance_score,
                "technical": technical_score,
            },
            "title": safe_text(title_tag),
            "meta_description": safe_text(meta_desc),
            "h1_count": len(h1_tags),
            "link_count": len(links),
            "image_count": len(images),
            "images_missing_alt": images_missing_alt,
            "viewport": "Var" if viewport_tag else "Yok",
            "canonical": canonical_tag.get("href") if canonical_tag and canonical_tag.get("href") else "Yok",
            "robots": "Var" if robots_exists else "Yok",
            "sitemap": "Var" if sitemap_exists else "Yok",
            "compression": compression,
            "page_size_kb": page_size_kb,
            "issue_counts": {
                "critical": critical_count,
                "medium": medium_count,
                "low": low_count,
            },
            "security_headers": security_headers,
            "passed_checks": passed_checks,
            "broken_links": broken_links,
            "issues": issues
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
