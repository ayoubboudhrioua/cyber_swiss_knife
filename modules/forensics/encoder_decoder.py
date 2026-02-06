# modules/forensics/encoder_decoder.py

import base64
import binascii
from urllib.parse import quote, unquote
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class EncoderDecoder:
    """
    Multi-format encoder/decoder tool
    """
    
    def encode_base64(self, data):
        """Encode to Base64"""
        return base64.b64encode(data.encode()).decode()
    
    def decode_base64(self, data):
        """Decode from Base64"""
        try:
            return base64.b64decode(data).decode()
        except Exception as e:
            return f"Error: {e}"
    
    def encode_hex(self, data):
        """Encode to hexadecimal"""
        return data.encode().hex()
    
    def decode_hex(self, data):
        """Decode from hexadecimal"""
        try:
            return bytes.fromhex(data).decode()
        except Exception as e:
            return f"Error: {e}"
    
    def encode_binary(self, data):
        """Encode to binary"""
        return ' '.join(format(ord(c), '08b') for c in data)
    
    def decode_binary(self, data):
        """Decode from binary"""
        try:
            # Remove spaces and split into 8-bit chunks
            binary = data.replace(' ', '')
            chars = [chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8)]
            return ''.join(chars)
        except Exception as e:
            return f"Error: {e}"
    
    def encode_url(self, data):
        """URL encode"""
        return quote(data)
    
    def decode_url(self, data):
        """URL decode"""
        return unquote(data)
    
    def encode_rot13(self, data):
        """ROT13 cipher"""
        result = []
        for char in data:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)
    
    def decode_rot13(self, data):
        """ROT13 decode (same as encode)"""
        return self.encode_rot13(data)
    
    def display_all_encodings(self, text):
        """Display text in all supported encodings"""
        
        console.print("\n[bold cyan]🔄 All Encodings[/bold cyan]\n")
        
        encodings = {
            'Base64': self.encode_base64(text),
            'Hexadecimal': self.encode_hex(text),
            'Binary': self.encode_binary(text),
            'URL Encoded': self.encode_url(text),
            'ROT13': self.encode_rot13(text),
        }
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Format", style="cyan", width=15)
        table.add_column("Encoded Value", style="yellow")
        
        for format_name, encoded in encodings.items():
            # Truncate long outputs
            display = encoded[:100] + "..." if len(encoded) > 100 else encoded
            table.add_row(format_name, display)
        
        console.print(table)

def run_encoder_decoder():
    """Interactive encoder/decoder menu"""
    tool = EncoderDecoder()
    
    console.print("\n[bold cyan]🔄 Encoder/Decoder Tool[/bold cyan]\n")
    
    # Menu
    console.print("[bold]Choose operation:[/bold]")
    console.print("1. Encode (show all formats)")
    console.print("2. Decode Base64")
    console.print("3. Decode Hexadecimal")
    console.print("4. Decode Binary")
    console.print("5. Decode URL")
    console.print("6. ROT13 (encode/decode)")
    
    choice = console.input("\n[cyan]Enter choice (1-6): [/cyan]").strip()
    
    if choice == "1":
        text = console.input("\n[cyan]Enter text to encode: [/cyan]")
        tool.display_all_encodings(text)
    
    elif choice == "2":
        encoded = console.input("\n[cyan]Enter Base64 string: [/cyan]")
        result = tool.decode_base64(encoded)
        console.print(f"\n[green]Decoded:[/green] {result}")
    
    elif choice == "3":
        encoded = console.input("\n[cyan]Enter hex string: [/cyan]")
        result = tool.decode_hex(encoded)
        console.print(f"\n[green]Decoded:[/green] {result}")
    
    elif choice == "4":
        encoded = console.input("\n[cyan]Enter binary string: [/cyan]")
        result = tool.decode_binary(encoded)
        console.print(f"\n[green]Decoded:[/green] {result}")
    
    elif choice == "5":
        encoded = console.input("\n[cyan]Enter URL encoded string: [/cyan]")
        result = tool.decode_url(encoded)
        console.print(f"\n[green]Decoded:[/green] {result}")
    
    elif choice == "6":
        text = console.input("\n[cyan]Enter text: [/cyan]")
        result = tool.encode_rot13(text)
        console.print(f"\n[green]ROT13:[/green] {result}")