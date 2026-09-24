import html
import math
import os
from pathlib import Path
import urllib.parse

SCRIPT_DIR = Path(__file__).parent

def format_size(size_bytes):
    if size_bytes == 0:
        return "0 B"
    size_name = ("B", "KB", "MB", "GB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"

def main():
    public_dir = Path('public')
    if not public_dir.exists():
        print("Error: public directory not found.")
        return

    repo = os.environ.get('GITHUB_REPOSITORY', 'openwrt-packages-extended')
    repo_name = repo.split('/')[-1] if '/' in repo else repo

    rows = []
    for file_path in sorted(public_dir.rglob('*')):
        if not file_path.is_file():
            continue
        rel_path = file_path.relative_to(public_dir).as_posix()
        if rel_path == 'index.html':
            continue

        url_path = urllib.parse.quote(rel_path)
        size = format_size(file_path.stat().st_size)
        
        if rel_path.endswith('.pub'):
            file_type = "key"
            icon = "🔑"
            badge_class = "badge-key"
            badge_text = "Public Key"
        elif rel_path.endswith('.apk') or rel_path.endswith('.ipk'):
            file_type = "pkg"
            icon = "📦"
            badge_class = "badge-pkg"
            badge_text = "Package"
        else:
            file_type = "meta"
            icon = "📄"
            badge_class = "badge-meta"
            badge_text = "Metadata"

        rows.append(
            f'<tr class="file-row" data-name="{html.escape(rel_path.lower())}" data-type="{file_type}">'
            f'<td class="file-name"><span class="icon">{icon}</span>'
            f'<a href="{url_path}">{html.escape(rel_path)}</a></td>'
            f'<td><span class="badge {badge_class}">{badge_text}</span></td>'
            f'<td class="file-size">{size}</td>'
            f'<td class="action-cell">'
            f'<a class="btn-download" href="{url_path}" download>Download</a>'
            f'</td></tr>'
        )

    template = (SCRIPT_DIR / 'index.template.html').read_text(encoding='utf-8')
    output = template.replace('{{REPO_NAME}}', html.escape(repo_name)).replace('{{TABLE_ROWS}}', '\n'.join(rows))

    output_path = public_dir / 'index.html'
    output_path.write_text(output, encoding='utf-8')
    print(f"Generated index at {output_path}")

if __name__ == '__main__':
    main()
