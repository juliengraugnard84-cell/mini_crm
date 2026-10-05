"""Exercise the actual export function with bundled PDF tools and synthetic data."""
import ast
import io
from datetime import date, datetime
from pathlib import Path
from pypdf import PdfReader

root = Path(__file__).resolve().parents[1]
source = ast.parse((root / 'app.py').read_text(encoding='utf-8'))
function = next(node for node in source.body if isinstance(node, ast.FunctionDef)
                and node.name == 'export_commercial_statistics_pdf')
function.decorator_list = []

signed = []
for i in range(12):
    revenues = [dict(date=date(2026, 2, 6), montant=100.25 + j,
                     dossier=f'REVENU-{i:03d}-{j:03d} - Contrat gaz et electricite - residence et copropriete')
                for j in range(18)]
    signed.append(dict(id=i + 1, name=f'SIGNE-{i:03d} - Foncia Paris residence avec un nom long & detail <site>',
                       siret='12345678900012', created_at=datetime(2026, 1, 5),
                       ca=sum(r['montant'] for r in revenues), revenues=revenues))
signed.append(dict(id=99, name='SIGNE-SANS-CA', siret=None, created_at=None, ca=0, revenues=[]))
lost = [dict(id=100 + i, name=f'PERDU-{i:03d} - Cythia residence regionale avec un nom tres long & annexe',
             siret='12345678900013', created_at=datetime(2026, 3, 5)) for i in range(45)]
signed_ca = sum(d['ca'] for d in signed)
stat = dict(commercial='Commercial test', career=dict(dossiers=58, gagnes=13, taux_gain=22.4,
            ca=signed_ca + 25.75, ca_moyen=100), years=[], signed_dossiers=signed,
            lost_dossiers=lost, signed_ca=signed_ca,
            other_revenues=[dict(date=date(2026, 3, 6), dossier='REVENU-NON-RATTACHE', montant=25.75)])
namespace = dict(io=io, date=date, build_commercial_statistics=lambda *args: [stat],
                 get_db=lambda: None, send_file=lambda buffer, **kwargs: buffer)
exec(compile(ast.Module(body=[function], type_ignores=[]), str(root / 'app.py'), 'exec'), namespace)
buffer = namespace['export_commercial_statistics_pdf'](1)
pdf_path = root / 'tmp' / 'pdfs' / 'statistics-export-verification.pdf'
pdf_path.parent.mkdir(parents=True, exist_ok=True)
pdf_path.write_bytes(buffer.getvalue())
reader = PdfReader(pdf_path)
text = '\n'.join(page.extract_text() for page in reader.pages)
compact = ''.join(text.split())
for dossier in signed:
    assert ''.join(dossier['name'].split()) in compact, dossier['name']
    for revenue in dossier['revenues']:
        assert ''.join(revenue['dossier'].split()) in compact, revenue['dossier']
for dossier in lost:
    assert ''.join(dossier['name'].split()) in compact, dossier['name']
assert 'REVENU-NON-RATTACHE' in text
assert '100,25 EUR' in text
assert 'Aucun revenu' in text
assert len(reader.pages) > 1
for number, page in enumerate(reader.pages, 1):
    assert f'Page {number}' in page.extract_text()
print(f'PDF verified: {len(reader.pages)} pages, {len(signed)} signed dossiers, '
      f'{sum(len(d["revenues"]) for d in signed)} revenue lines, {len(lost)} lost dossiers.')
print(pdf_path)
