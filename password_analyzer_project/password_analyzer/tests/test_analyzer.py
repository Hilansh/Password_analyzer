import unittest
from password_analyzer import analyze_password

class AnalyzerTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(analyze_password("").rating, "Very Weak")
    def test_common_password(self):
        self.assertTrue(analyze_password("Password123!").flags["common"])
    def test_sequence(self):
        self.assertTrue(analyze_password("abcXYZ987!").flags["sequence"])
    def test_keyboard(self):
        self.assertTrue(analyze_password("Qwerty!2026").flags["keyboard"])
    def test_repetition(self):
        self.assertTrue(analyze_password("aaaaBBB!2026").flags["repeated"])
    def test_date(self):
        self.assertTrue(analyze_password("BlueTiger1998!").flags["date"])
    def test_context(self):
        self.assertTrue(analyze_password("Hilansh!LongPhrase2026", ["Hilansh"]).flags["context"])
    def test_unicode(self):
        self.assertTrue(analyze_password("correct horse battery staple 🔐").character_types["unicode"])
    def test_long_password(self):
        self.assertGreaterEqual(analyze_password("mango-river-cloud-lantern-forest").length, 30)

if __name__ == "__main__": unittest.main()
