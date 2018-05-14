from utils import *
from image_utils import website_render
from image_utils import image_process
import unittest

class test_main(unittest.TestCase):
    def test_split_domain(self):
        self.assertTrue(remove_tld("paypal.com") == "paypal")
        self.assertTrue(remove_tld("test"))

    def test_phantomjs(self):
        r = website_render.website_render()
        self.assertTrue(r.render_webpage("https://iosiro.com"))

    def test_website_comparison(self):
        r = website_render.website_render()
        page1 = r.render_webpage("https://iosiro.com")
        page2 = r.render_webpage("https://facebook.com")
        improc = image_process.image_utils()
        similarity = improc.image_similarity(page1, page1)
        print("Similarity between iosiro + iosiro {}".format(similarity))
        self.assertEqual(1.0, similarity)
        similarity = improc.image_similarity(page1, page2)
        print("Similarity between iosiro + facebook {}".format(similarity))
        self.assertNotEqual(1.0, similarity)

        page1 = r.render_webpage("https://myetherwallet.com")
        page2 = r.render_webpage("http://myetherwallwt.com/")
        similarity = improc.image_similarity(page1, page2)
        print("Similarity between phishing page + mew {}".format(similarity))
    
    def test_website_blank_comparison(self):
        r = website_render.website_render()
        page1 = r.render_webpage("https://iosiro.com")
        page2 = r.render_webpage("https://thisdoesntexist3432415.com")
        improc = image_process.image_utils()
        similarity = improc.image_similarity(page1, page1)
        print("Similarity between iosiro + iosiro {}".format(similarity))
        self.assertNotEqual(0.0, similarity)

def main():
    unittest.main()


if __name__ == '__main__':
    main()
