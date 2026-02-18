import importlib.util
import inspect
from pathlib import Path
from abc import ABC, abstractmethod
from rich.console import Console
from rich.table import Table

console = Console()
class Pluginbase(ABC):
    """Base class that all plugins must inherit from
    this defines the plugin interface"""
    @abstractmethod
    def get_name(self):
        """Return plugin name"""
        pass
    @abstractmethod
    def get_description(self):
        """Return plugin description"""
        pass
    
    @abstractmethod
    def get_version(self):
        """Return plugin version"""
        pass
    
    @abstractmethod
    def execute(self, *args, **kwargs):
        """Main plugin execution method"""
        pass
    
    def get_author(self):
        """Return plugin author (optional)"""
        return "Unknown"
    
    def get_category(self):
        """Return plugin category (optional)"""
        return "General"

class PluginManager:
    """Plugin manager that discovers and loads plugins"""
    def __init__(self,plugin_dir="plugins"):
        self.plugin_dir = Path(plugin_dir)
        self.plugin_dir.mkdir(exist_ok=True)
        self.plugins = {}
        self.load_plugins()
    def load_plugins(self):
        """Discover and load all plugins from plugins directory"""
        console.print(f"[dim]Loading plugins from {self.plugin_dir}...[/dim]")
        #Find all python files in plugin directory
        plugin_files = list(self.plugin_dir.glob("*.py"))
        for plugin_file in plugin_files:
            if plugin_file.name.startswith("_"):
                continue #Skip files starting with underscore
            try:
                #Load module dynamically
                spec = importlib.util.spec_from_file_location(
                    plugin_file.stem,
                    plugin_file
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                # Find plugin classes (subclasses of pluginBase)
                for name,obj in inspect.getmembers(module):
                    if (inspect.isclass(obj) and issubclass(obj, Pluginbase) and obj is not Pluginbase):
                        
                        plugin_instance = obj()
                        plugin_name = plugin_instance.get_name()
                        
                        self.plugins[plugin_name] = plugin_instance
                        console.print(f" ✅ Loaded: {plugin_name}")
            except Exception as e:
                console.print(f" ❌ Error loading {plugin_file.name}: {e}")
    def list_plugins(self):
        """List all loaded plugins"""
        
        if not self.plugins:
            console.print("[yellow]No plugins loaded[/yellow]")
            return
        
        table = Table(
            title="🔌 Available Plugins",
            show_header=True,
            header_style="bold magenta"
        )
        table.add_column("Name", style="cyan", width=20)
        table.add_column("Version", style="yellow", width=10)
        table.add_column("Category", style="green", width=15)
        table.add_column("Description", style="white")
        
        for plugin in self.plugins.values():
            table.add_row(
                plugin.get_name(),
                plugin.get_version(),
                plugin.get_category(),
                plugin.get_description()
            )
        
        console.print(table)
    def get_plugin(self,name):
        """Get a specific plugin by name"""
        return self.plugins.get(name)
    def execute_plugin(self,name,*args,**kwargs):
        """Execute a plugin by name"""
        plugin = self.get_plugin(name)
        if plugin is None:
            console.print(f"[red]Plugin '{name}' not found[/red]")
            return None
        
        try:
            console.print(f"\n[bold cyan]Executing: {plugin.get_name()}[/bold cyan]")
            result = plugin.execute(*args, **kwargs)
            return result
        except Exception as e:
            console.print(f"[red]Error executing plugin: {e}[/red]")
            return None
    def reload_plugins(self):
        """Reload all plugins"""
        self.plugin = {}
        self.load_plugins()
        console.print("[green]✅ Plugins reloaded[/green]")
        
        
def run_plugins_manager():
    """Interactive plugin manager"""
    manager = PluginManager()
    
    console.print("\[bold cyan]🔌 Plugin Manager[/bold cyan]\n")
    while True:
        console.print("\n[bold]Options:[/bold]")
        console.print("1. List plugins")
        console.print("2. Execute plugin")
        console.print("3. Reload plugins")
        console.print("4. Plugin development guide")
        console.print("0. Back to main menu")
        
        choice = console.input("\n[cyan]Choice: [/cyan]").strip()
        if choice == "0":
            break
        elif choice == "1":
            manager.list_plugins()
        elif choice == "2":
            plugin_name = console.input("[cyan]Enter plugin name: [/cyan]")
            manager.execute_plugin(plugin_name)
        elif choice == "3":
            manager.reload_plugins()
        elif choice == "4":
            show_plugin_development_guide()
        else:
            console.print("[red]Invalid choice[/red]")
def show_plugin_development_guide():
    """Show guide for developing plugins"""
    from rich.panel import Panel
    guide = """
[bold]How to Create a Plugin:[/bold]

1. Create a new Python file in the 'plugins/' directory
2. Import PluginBase: from modules.plugins.plugin_manager import PluginBase
3. Create a class that inherits from PluginBase
4. Implement required methods:
   - get_name()
   - get_description()
   - get_version()
   - execute()

[bold yellow]Example Plugin:[/bold yellow]
```python
from modules.plugins.plugin_manager import PluginBase
from rich.console import Console

console = Console()

class HelloWorldPlugin(PluginBase):
    def get_name(self):
        return "hello_world"
    
    def get_description(self):
        return "A simple hello world plugin"
    
    def get_version(self):
        return "1.0.0"
    
    def get_category(self):
        return "Demo"
    
    def execute(self):
        console.print("[green]Hello from plugin![/green]")
        name = console.input("What's your name? ")
        console.print(f"[cyan]Nice to meet you, {name}![/cyan]")
```

Save this as 'plugins/hello_world.py' and it will be auto-loaded!
"""
    console.print(Panel(guide,title="Plugin Development Guide", border_style="cyan"))
    
        