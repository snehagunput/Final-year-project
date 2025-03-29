import cv2

def process_image(img):
    # Example processing: Convert image to grayscale
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    # For demonstration, let’s say you return the average pixel intensity
    avg_intensity = float(gray.mean())
    return {'avg_intensity': avg_intensity}
