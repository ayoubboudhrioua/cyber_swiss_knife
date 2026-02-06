
import os
import hashlib
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class MetadataExtractor:
    """
    Extract and analyze file metadata
    """
    
    def extract_metadata(self, file_path):
        """Extract comprehensive file metadata"""
        
        path = Path(file_path)
        
        if not path.exists():
            return {'error': 'File not found'}
        
        # Get file stats
        stats = path.stat()
        
        # Calculate hashes
        hashes = self.calculate_hashes(file_path)
        
        # File info
        metadata = {
            'Basic Information': {
                'Filename': path.name,
                'Full Path': str(path.absolute()),
                'Extension': path.suffix,
                'Size (bytes)': stats.st_size,
                'Size (human)': self.format_size(stats.st_size),
            },
            'Timestamps': {
                'Created': datetime.fromtimestamp(stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                'Modified': datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                'Accessed': datetime.fromtimestamp(stats.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
            },
            'Permissions': {
                'Mode': oct(stats.st_mode),
                'Owner UID': stats.st_uid,
                'Group GID': stats.st_gid,
            },
            'Hashes': hashes,
            'Content Analysis': self.analyze_content(file_path),
        }
        
        return metadata
    
    def calculate_hashes(self, file_path):
        """Calculate multiple hashes for file"""
        
        hashes = {}
        hash_functions = {
            'MD5': hashlib.md5(),
            'SHA-1': hashlib.sha1(),
            'SHA-256': hashlib.sha256(),
            'SHA-512': hashlib.sha512(),
        }
        
        try:
            with open(file_path, 'rb') as f:
                # Read in chunks for large files
                while chunk := f.read(8192):
                    for hash_obj in hash_functions.values():
                        hash_obj.update(chunk)
            
            for name, hash_obj in hash_functions.items():
                hashes[name] = hash_obj.hexdigest()
        
        except Exception as e:
            hashes['Error'] = str(e)
        
        return hashes
    
    def analyze_content(self, file_path):
        """Analyze file content characteristics"""
        
        analysis = {}
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read(1024)  # Read first 1KB
            
            # File type detection
            if content.startswith(b'%PDF'):
                analysis['Type'] = 'PDF Document'
            elif content.startswith(b'\x89PNG'):
                analysis['Type'] = 'PNG Image'
            elif content.startswith(b'\xff\xd8\xff'):
                analysis['Type'] = 'JPEG Image'
            elif content.startswith(b'PK\x03\x04'):
                analysis['Type'] = 'ZIP Archive or Office Document'
            elif content.startswith(b'#!/'):
                analysis['Type'] = 'Script/Executable'
            elif all(32 <= byte < 127 or byte in [9, 10, 13] for byte in content[:100]):
                analysis['Type'] = 'Text File'
            else:
                analysis['Type'] = 'Binary File'
            
            # Entropy (randomness)
            entropy = self.calculate_entropy(content)
            analysis['Entropy'] = f"{entropy:.2f} bits/byte"
            
            if entropy > 7.5:
                analysis['Note'] = 'High entropy - likely compressed or encrypted'
            
        except Exception as e:
            analysis['Error'] = str(e)
        
        return analysis
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        import math
        
        if not data:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        
        return entropy
    
    def format_size(self, size):
        """Format size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    
    def display_metadata(self, metadata):
        """Display metadata beautifully"""
        
        if 'error' in metadata:
            console.print(f"[red]❌ {metadata['error']}[/red]")
            return
        
        console.print("\n[bold cyan]📁 File Metadata Analysis[/bold cyan]\n")
        
        for category, data in metadata.items():
            table = Table(
                title=category,
                show_header=True,
                header_style="bold magenta"
            )
            table.add_column("Property", style="cyan", width=20)
            table.add_column("Value", style="yellow")
            
            for key, value in data.items():
                table.add_row(key, str(value))
            
            console.print(table)
            console.print()

def run_metadata_extractor():
    """Interactive metadata extractor"""
    extractor = MetadataExtractor()
    
    console.print("\n[bold cyan]📁 File Metadata Extractor[/bold cyan]")
    file_path = console.input("\n[cyan]Enter file path: [/cyan]").strip()
    
    with console.status("[bold green]Analyzing file..."):
        metadata = extractor.extract_metadata(file_path)
    
    extractor.display_metadata(metadata)