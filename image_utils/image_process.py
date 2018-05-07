'''

This is currently a work in progress and not implemented yet. The challenges to solve:

    - Add website screenshots from selenium
    - Size the images similarly so that you can measure the similarity using ssim

'''

from PIL import Image
import numpy as np
import matplotlib.pyplot as plt
from skimage import io
from skimage import data, img_as_float
import sys
from random import randint
import os
from image_utils import website_render
from skimage.measure import compare_ssim as ssim

class image_utils:
    def __init__(self):
        self.web_render = website_render.website_render()

    def ssim_wrapper(self, image1_location, image2_location):
        img1 = img_as_float(io.imread(image1_location))
        print(img1.size)
        rows1, cols1, other = img1.shape

        img2 = img_as_float(io.imread(image2_location))
        rows2, cols2, other = img2.shape

        return ssim(img1, img2, data_range=img1.max() - img1.min(),multichannel=True)

    def image_similarity(self, image1_path, image2_path):
        img1 = Image.open(image1_path)
        width1, height1 = img1.size

        img2 = Image.open(image2_path)
        width2, height2 = img2.size

        height = min([height1, height2])
        width = min([width1, width2])
        if height < 250 or width < 250:
            #If the image is too small, we can't rely on this.
            return -1

        image1_cropped = self.convert_image_to_jpeg(self.crop_image(image1_path, size=(width, height)))
        image2_cropped = self.convert_image_to_jpeg(self.crop_image(image2_path, size=(width, height)))

        result = self.ssim_wrapper(image1_cropped, image2_cropped)
        os.remove(image1_cropped)
        os.remove(image2_cropped)
        return result

    def convert_image_to_jpeg(self,image_path, quality=15):
        png = Image.open(image_path).convert('RGBA')
        background = Image.new('RGBA', png.size, (255,255,255))

        new_image = '/tmp/{}.jpg'.format(randint(0,1000000000))

        alpha_composite = Image.alpha_composite(background, png)
        alpha_composite.save(new_image, 'JPEG', quality=quality)
        return new_image

    def compare_website_visually(self, url1, url2):
        image_path1 = self.web_render.render_webpage(url1)
        image_path2 = self.web_render.render_webpage(url2)
        return self.image_similarity(image_path1, image_path2)

    def crop_image(self, image_path, size=(600,600)):
        print("cropping to size: {}".format(size))
        img = Image.open(image_path)
        img = img.crop((0, 0, size[0], size[1]))
        img_name = '/tmp/{}.jpg'.format(str(randint(0,10000000000)))
        print("saved cropped image to {}".format(img_name))
        img.save(img_name)
        return img_name
