"""Commission configuration and immutable rate snapshots on revenue entries."""
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from datetime import date

SOURCE_RATES = {'ade': Decimal('35'), 'direct': Decimal('50')}


def revenue_breakdown(amount, source):
    if source not in SOURCE_RATES:
        raise ValueError('Choisissez ADE ou Fournisseur en direct.')
    try:
        amount = Decimal(str(amount).replace(' ', '').replace('\u202f', '').replace('\u00a0', '').replace(',', '.'))
        if not amount.is_finite() or amount <= 0 or amount > Decimal('999999999999.99') or amount != amount.quantize(Decimal('.01')):
            raise ValueError()
    except (InvalidOperation, ValueError):
        raise ValueError('Saisissez une somme initiale positive avec au maximum deux décimales.')
    retained = (amount * SOURCE_RATES[source] / 100).quantize(Decimal('.01'), rounding=ROUND_HALF_UP)
    return amount, retained, amount - retained


def ensure_commissions_schema(conn):
    with conn.cursor() as cur:
        for table, column in [('users', 'commission_rate'), ('users', 'direct_commission_rate'), ('revenus', 'commission_rate'),
                              ('revenus', 'aleo_rate')]:
            cur.execute(f'ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} NUMERIC(5,2) CHECK ({column} BETWEEN 0 AND 100)')
        cur.execute('ALTER TABLE revenus ADD COLUMN IF NOT EXISTS initial_amount NUMERIC(14,2)')
        cur.execute('ALTER TABLE revenus ADD COLUMN IF NOT EXISTS revenue_source TEXT')
        cur.execute('ALTER TABLE revenus ADD COLUMN IF NOT EXISTS supplier_rate NUMERIC(5,2)')
        cur.execute('ALTER TABLE revenus ADD COLUMN IF NOT EXISTS supplier_name TEXT')
        cur.execute('ALTER TABLE revenus ADD COLUMN IF NOT EXISTS signed_on DATE')
        cur.execute('ALTER TABLE revenus ADD COLUMN IF NOT EXISTS energy_type TEXT')
        cur.execute("ALTER TABLE revenus ADD COLUMN IF NOT EXISTS payment_status TEXT DEFAULT 'to_invoice' CHECK (payment_status IN ('to_invoice', 'invoiced', 'paid'))")
        cur.execute('ALTER TABLE revenus ADD COLUMN IF NOT EXISTS invoiced_on DATE')
        cur.execute('ALTER TABLE revenus ADD COLUMN IF NOT EXISTS paid_on DATE')
    conn.commit()


def parse_rate(value):
    try:
        rate = Decimal(value.strip().replace(',', '.'))
        if not rate.is_finite() or not 0 <= rate <= 100 or rate != rate.quantize(Decimal('.01')):
            raise ValueError()
        return rate
    except (InvalidOperation, ValueError, AttributeError):
        raise ValueError('Le taux doit être compris entre 0 et 100, avec au maximum deux décimales.')


def contract_details(form, required=True):
    raw_date = (form.get('signed_on') or '').strip()
    energy = (form.get('energy_type') or '').strip()
    try:
        signed_on = date.fromisoformat(raw_date) if raw_date else None
    except ValueError:
        raise ValueError('La date de signature est invalide.')
    if signed_on and signed_on.year > 9998:
        raise ValueError('La date de signature est invalide.')
    if energy not in ('', 'electricite', 'gaz', 'electricite_gaz'):
        raise ValueError("Choisissez une énergie valide.")
    if required and (not signed_on or not energy):
        raise ValueError("Renseignez la date de signature et l'énergie du contrat.")
    return signed_on, energy or None


def insert_revenue(cur, revenue_date, commercial, dossier, client_id, amount, source, supplier_name=None,
                   signed_on=None, energy_type=None):
    initial, retained, net = revenue_breakdown(amount, source)
    # A single statement snapshots the configured rate alongside the CA.
    cur.execute('''
        INSERT INTO revenus (date, commercial, dossier, client_id, montant, commission_rate, aleo_rate,
                             initial_amount, revenue_source, supplier_rate, supplier_name, signed_on, energy_type)
        SELECT %s, %s, %s, %s, %s,
               CASE WHEN %s = 'ade' THEN u.commission_rate ELSE u.direct_commission_rate END,
               100 - CASE WHEN %s = 'ade' THEN u.commission_rate ELSE u.direct_commission_rate END,
               %s, %s, %s, %s, %s, %s
        FROM (SELECT 1) seed
        LEFT JOIN users u ON u.username = %s
    ''', (revenue_date, commercial, dossier, client_id, net, source, source, initial, source, SOURCE_RATES[source], supplier_name, signed_on, energy_type, commercial))


def commission_values(row):
    rate, aleo_rate = row.get('commission_rate'), row.get('aleo_rate')
    if rate is None or aleo_rate is None:
        return None
    amount = Decimal(str(row['montant']))
    commercial = (amount * Decimal(str(rate)) / 100).quantize(Decimal('.01'), rounding=ROUND_HALF_UP)
    # Preserve the full CA down to the cent when the shares are complementary.
    aleo = amount.quantize(Decimal('.01'), rounding=ROUND_HALF_UP) - commercial
    return commercial, aleo
