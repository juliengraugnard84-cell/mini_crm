import os
import unittest
from html.parser import HTMLParser
from pathlib import Path

os.environ['LOCAL_MODE'] = '1'
import app as crm


class UsabilityTests(unittest.TestCase):
    def context(self, role):
        return dict(current_user=dict(id=1, username='Alice', role=role), csrf_token='test',
                    available_endpoints=list(crm.app.view_functions), unread_cotations=2,
                    unread_updates=1, unread_duplicate_alerts=0)

    def test_all_templates_compile(self):
        for file in Path(crm.app.template_folder).glob('*.html'):
            with self.subTest(template=file.name):
                crm.app.jinja_env.get_template(file.name)

    def test_admin_navigation_has_one_cotation_entry_and_rate_settings(self):
        with crm.app.test_request_context('/admin/commissions'):
            html = crm.app.jinja_env.get_template('navigation.html').render(**self.context('admin'))
        self.assertEqual(html.count('href="/admin/cotations"'), 1)
        self.assertNotIn('Mes cotations', html)
        self.assertIn('href="/admin/commissions"', html)
        self.assertIn('aria-current="page"', html)
        self.assertIn('href="/commissions/releves"', html)

    def test_commercial_navigation_does_not_expose_admin_pages(self):
        with crm.app.test_request_context('/commissions'):
            html = crm.app.jinja_env.get_template('navigation.html').render(**self.context('commercial'))
        self.assertNotIn('href="/admin/', html)
        self.assertNotIn('Taux de commission', html)
        self.assertIn('Relevés et facturation', html)

    def test_status_controls_are_not_nested_in_navigation_links(self):
        class Parser(HTMLParser):
            anchor = False
            nested_form = False
            def handle_starttag(self, tag, attrs):
                if tag == 'a': self.anchor = True
                if tag == 'form' and self.anchor: self.nested_form = True
            def handle_endtag(self, tag):
                if tag == 'a': self.anchor = False
        with crm.app.test_request_context('/clients'):
            context = self.context('commercial')
            module = crm.app.jinja_env.get_template('clients.html').make_module(context)
            html = module.render_client_column('En cours', [dict(id=1, name='Dossier', commercial='Alice', status='en_cours')], '', '')
        parser = Parser()
        parser.feed(html)
        self.assertFalse(parser.nested_form)
        self.assertIn('aria-label="Statut de Dossier"', html)


if __name__ == '__main__':
    unittest.main()
