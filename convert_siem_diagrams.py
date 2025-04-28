#!/usr/bin/env python3
"""
Convert SVG SIEM diagrams to PNG format
"""
import os
import cairosvg

def convert_svg_to_png(svg_path, png_path):
    """Convert an SVG file to PNG format"""
    print(f"Converting {svg_path} to {png_path}")
    try:
        cairosvg.svg2png(url=svg_path, write_to=png_path, dpi=300)
        print(f"Converted {svg_path} successfully")
    except Exception as e:
        print(f"Error converting {svg_path}: {e}")

def main():
    """Convert all SVG SIEM diagrams to PNG format"""
    svg_dir = './static/images/siem_diagrams/'
    png_dir = './static/images/siem_diagrams/png/'
    
    # Ensure the PNG directory exists
    os.makedirs(png_dir, exist_ok=True)
    
    # Get all SVG files in the directory
    svg_files = [f for f in os.listdir(svg_dir) if f.endswith('.svg')]
    
    # Convert each SVG file to PNG
    for svg_file in svg_files:
        svg_path = os.path.join(svg_dir, svg_file)
        png_file = os.path.splitext(svg_file)[0] + '.png'
        png_path = os.path.join(png_dir, png_file)
        convert_svg_to_png(svg_path, png_path)
    
    print(f"Converted {len(svg_files)} SVG files to PNG format")

if __name__ == "__main__":
    main()