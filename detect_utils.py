import torchvision.transforms as transforms
import cv2
import numpy as np

from coco_names import COCO_INSTANCE_CATEGORY_NAMES as coco_names

# this will help us create a different color for each class
COLORS = np.random.uniform(0, 255, size=(len(coco_names), 3))

# define the torchvision image transforms
transform = transforms.Compose([
    transforms.ToTensor(),
])

def predict(image, model, device, detection_threshold):

    
    image = transform(image).to(device) # convert image to tensor
    image = image.unsqueeze(0) # add dim for batch_size
    outputs = model(image) # get the pred for the image

    # get all scores for predicted classes
    pred_scores = outputs[0]['scores'].detach().cpu().numpy()

    # get all predicted bounding boxes
    pred_bbox = outputs[0]['boxes'].detach().cpu().numpy()

    # keep boes with scores >= threshold
    boxes = pred_bbox[ pred_scores >= detection_threshold].astype(np.int32)

    # get labels for pred above threshold
    labels = outputs[0]['labels'][ pred_scores >= detection_threshold ].cpu().numpy().astype(np.int32)

    # get all predicted clases
    pred_classes = [ coco_names[i] for i in outputs[0]['labels'].cpu().numpy() ]

    return boxes, pred_classes, labels


def draw_boxes(boxes, classes, labels, image):

    # read the image with OpenCV
    image = cv2.cvtColor(np.asarray(image), cv2.COLOR_BGR2RGB)
    for i, box in enumerate(boxes):
        color = COLORS[labels[i]]
        cv2.rectangle(
            image,
            (int(box[0]), int(box[1])),
            (int(box[2]), int(box[3])),
            color, 2
        )
        cv2.putText(image, classes[i], (int(box[0]), int(box[1]-5)),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.8, color, 2, 
                    lineType=cv2.LINE_AA)
    return image