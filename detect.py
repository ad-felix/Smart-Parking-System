import torchvision
import numpy as np
import torch
# import argparse
# import cv2
import detect_utils
# from PIL import Image

def run(image):

    # download or load the model from disk
    model = torchvision.models.detection.fasterrcnn_resnet50_fpn(pretrained=True) # min_size=args['min_size']

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    model.eval().to(device)

    boxes, classes, labels = detect_utils.predict(image, model, device, 0.8)
    image = detect_utils.draw_boxes(boxes, classes, labels, image)

    return image