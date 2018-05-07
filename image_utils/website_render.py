import selenium
from selenium import webdriver
from time import sleep
from random import randint
from expiringdict import ExpiringDict

class website_render:
    def __init__(self):
        self.driver = webdriver.PhantomJS() # or add to your PATH
        self.driver.set_window_size(1024, 768) # optional
        self.fetched_cache = ExpiringDict(max_len=15000, max_age_seconds=(60*60)*24)

    def render_webpage(self, url):
        if self.fetched_cache.get(url, False):
            return self.fetched_cache.get(url)
        self.driver.get(url)
        file_path = "/tmp/{}.jpg".format(str(randint(0,10000000000000)))
        self.driver.save_screenshot(file_path) # save a screenshot to disk
        self.fetched_cache[url] = file_path
        return file_path
