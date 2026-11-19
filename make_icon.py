"""Generates icon-1024.png for `tauri icon`: dark tile with a download (blue) and upload (amber) bar."""
from PIL import Image, ImageDraw, ImageFilter

S = 1024
img = Image.new('RGBA', (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
d.rounded_rectangle((64, 64, S - 64, S - 64), radius=210, fill=(22, 26, 33, 255), outline=(44, 52, 64, 255), width=10)

glow = Image.new('RGBA', (S, S), (0, 0, 0, 0))
g = ImageDraw.Draw(glow)
bars = [((300, 330, 470, 800), (90, 169, 255)), ((554, 470, 724, 800), (255, 169, 77))]
for box, c in bars:
    g.rounded_rectangle(box, radius=60, fill=c + (150,))
glow = glow.filter(ImageFilter.GaussianBlur(40))
img.alpha_composite(glow)
d = ImageDraw.Draw(img)
for box, c in bars:
    d.rounded_rectangle(box, radius=60, fill=c + (255,))
# arrow heads
d.polygon([(385, 860), (325, 790), (445, 790)], fill=(90, 169, 255, 255))
d.polygon([(639, 400), (579, 470), (699, 470)], fill=(255, 169, 77, 255))
img.save('icon-1024.png')
