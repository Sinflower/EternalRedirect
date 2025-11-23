import json

FONT_PATH = "mplus-1c-medium.ttf"
FONT_SIZE = 16

# Get the pixel length of the string rendered with the given font
def get_pixel_length(text, font_size=FONT_SIZE):
	from PIL import ImageFont, Image, ImageDraw

	font = ImageFont.truetype(FONT_PATH, font_size)
	if hasattr(font, "getbbox"):
		bbox = font.getbbox(text)
		return bbox[2] - bbox[0]

	img = Image.new("RGB", (1, 1))
	draw = ImageDraw.Draw(img)
	bbox = draw.textbbox((0, 0), text, font=font)
	return bbox[2] - bbox[0]

def fix_box_length_string(data):
	for key, value in data.items():
		# Skip all entires where the key does not contain a '\n'
		if '\n' not in key:
			continue

		parts = key.split('\n')

		# Iterate over the parts and check if any part is a key in data
		largest_part = None
		for part in parts:
			if part in data:
				if largest_part is None or len(part) >= len(largest_part):
					largest_part = part

		if largest_part is None:
			continue

		value_parts = value.split('\n')
		largest_value_part = max(value_parts, key=lambda x: (get_pixel_length(x), x))
		data[largest_part] = largest_value_part

def add_pixel_length_info(data):
	for key, value in data.items():
		parts = value.split('\n')
		lengths = [get_pixel_length(part) for part in parts]
		data[key] = {
			"text": value,
			"pixel_lengths": lengths
		}

with open('tr_org.json', 'r', encoding='utf-8') as file:
	data = json.load(file)

fix_box_length_string(data)
add_pixel_length_info(data)

with open('tr.json', 'w', encoding='utf-8') as file:
	json.dump(data, file, ensure_ascii=False, indent=4)
