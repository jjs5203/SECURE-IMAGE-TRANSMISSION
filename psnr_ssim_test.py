import cv2
from skimage.metrics import structural_similarity as ssim

# --------------------------
# CONFIGURE INPUT FILE PATHS
# --------------------------

original_image_path = "images.jpg"       # your original image
decrypted_image_path = "output.png"      # your decrypted image

# --------------------------
# LOAD IMAGES
# --------------------------

img1 = cv2.imread(original_image_path)
img2 = cv2.imread(decrypted_image_path)

if img1 is None:
    print("Error: Could not read original image:", original_image_path)
    exit(1)

if img2 is None:
    print("Error: Could not read decrypted image:", decrypted_image_path)
    exit(1)

# Match sizes if needed
if img1.shape != img2.shape:
    print("Warning: Images differ in size. Resizing decrypted image...")
    img2 = cv2.resize(img2, (img1.shape[1], img1.shape[0]))

# --------------------------
# PSNR
# --------------------------

psnr_value = cv2.PSNR(img1, img2)

# --------------------------
# SSIM (convert to grayscale)
# --------------------------

gray1 = cv2.cvtColor(img1, cv2.COLOR_BGR2GRAY)
gray2 = cv2.cvtColor(img2, cv2.COLOR_BGR2GRAY)

ssim_value, _ = ssim(gray1, gray2, full=True)

# --------------------------
# REPORT
# --------------------------

print("========== IMAGE INTEGRITY REPORT ==========")
print(f"PSNR  : {psnr_value:.4f} dB")
print(f"SSIM  : {ssim_value:.6f}")
print("============================================")

# PASS / FAIL
if psnr_value > 40 and ssim_value > 0.95:
    print("Integrity: PASS ✓ (Images match almost perfectly)")
else:
    print("Integrity: FAIL ✗ (Images do not perfectly match)")
