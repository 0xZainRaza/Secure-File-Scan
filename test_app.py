import unittest
from app import app, db, User, Company, Malware, Report
from flask_login import FlaskLoginClient
from flask_testing import TestCase
from unittest.mock import patch

class TestApp(TestCase):
    def create_app(self):
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        return app

    def setUp(self):
        # Create tables and add test data
        with app.app_context():
            db.create_all()

            # Add a company and user
            self.company = Company(company_name="Test Company")
            db.session.add(self.company)
            db.session.commit()

            self.user = User(firstname="John", lastname="Doe", email="john.doe@example.com", password="password", company_id=self.company.company_id)
            db.session.add(self.user)
            db.session.commit()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_home_page(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_no_results_page(self):
        response = self.client.get('/noresults')
        self.assertEqual(response.status_code, 200)

    @patch('app.calculate_md5_hash')
    @patch('app.calculate_sha256_hash')
    @patch('app.get_virus_total_info')
    @patch('app.get_malware_bazaar_info')
    def test_results_page(self, mock_malware_bazaar, mock_virus_total, mock_sha256, mock_md5):
        # Mock the functions
        mock_md5.return_value = 'mock_md5_hash'
        mock_sha256.return_value = 'mock_sha256_hash'
        mock_virus_total.return_value = {
            'data': {
                'attributes': {
                    'crowdsourced_yara_results': [],
                    'type_description': 'Malware Type',
                    'type_tags': ['tag1'],
                    'names': ['name1']
                }
            }
        }
        mock_malware_bazaar.return_value = {'response': 'mock_response'}

        response = self.client.get('/results/testfile')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'mock_md5_hash', response.data)
        self.assertIn(b'mock_sha256_hash', response.data)

    def test_delete_account(self):
        with self.client:
            self.client.post('/login', data=dict(email="john.doe@example.com", password="password"))
            response = self.client.get('/deleteacount')
            self.assertRedirects(response, '/login')

    @patch('app.send_verification_email')
    def test_send_verification_email(self, mock_send_email):
        mock_send_email.return_value = None  # Mocking the email sending function
        email = 'john.doe@example.com'
        verification_code = 'mock_code'
        response = self.client.get(f'/send_verification_email/{email}/{verification_code}')
        self.assertEqual(response.status_code, 200)
        mock_send_email.assert_called_once_with(email, verification_code)

    def test_malware_submission_form(self):
        form = Malwareform(Mname="Test Malware", Mcategory="Category", Mtsystem="Windows", Fhash="mock_hash", Yrule="mock_rule", description="test")
        self.assertTrue(form.validate())

    def test_invalid_malware_submission_form(self):
        form = Malwareform(Mname="", Mcategory="Category", Mtsystem="Windows", Fhash="mock_hash", Yrule="mock_rule", description="test")
        self.assertFalse(form.validate())

if __name__ == '__main__':
    unittest.main()
