from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext
from com.pnfsoftware.jeb.core.units import IUnit

class dump_jeb(IScript):
    """
    This script inspects a specific native library unit within the currently
    opened project and dumps its available methods and properties. This helps
    in understanding the JEB API for a specific version.
    """
    def run(self, ctx):
        if not isinstance(ctx, IGraphicalClientContext):
            print("This script must be run within a graphical client.")
            return

        print("--- JEB API Inspector ---")

        # The name of the library to inspect.
        target_lib_name = "libnative-lib.so"

        # 1. Get the project
        prj = ctx.getMainProject()
        if not prj:
            print("Error: No project is open. Please open an APK file first.")
            return
        print("Successfully got project: %s" % prj.getName())

        # 2. Find the target native library unit
        native_unit = self.find_unit_by_name(prj, target_lib_name)

        if not native_unit:
            print("\nError: Could not find the unit '%s'." % target_lib_name)
            print("Please ensure the APK is fully analyzed and the library exists.")
            # As a fallback, let's dump the main unit of the first artifact
            artifacts = prj.getLiveArtifacts()
            if artifacts:
                main_unit = artifacts[0].getMainUnit()
                if main_unit:
                    print("\n--- Fallback: Dumping Main Unit ('%s') ---" % main_unit.getName())
                    self.inspect_object(main_unit, "Main Unit")
            return

        # 3. Inspect the found native unit
        self.inspect_object(native_unit, "Native Unit: '%s'" % native_unit.getName())

        # 4. Also inspect its processor to see what's available there
        if hasattr(native_unit, 'getProcessor'):
            processor = native_unit.getProcessor()
            if processor:
                self.inspect_object(processor, "Processor for '%s'" % native_unit.getName())
            else:
                print("\nUnit '%s' has getProcessor method, but it returned None." % native_unit.getName())
        
        print("\n--- Inspection Complete ---")
        print("This script's purpose was to dump the methods of the native library unit.")
        print("Please provide this full output to continue.")

    def find_unit_by_name(self, prj, name):
        """Recursively search for a unit by name in the first artifact."""
        artifacts = prj.getLiveArtifacts()
        if not artifacts:
            print("No live artifacts found in the project.")
            return None

        # We'll search in the first artifact, starting from its main unit.
        # We discovered getMainUnit() from the previous inspection run.
        root = artifacts[0].getMainUnit()
        if not root:
            print("First artifact has no main unit.")
            return None
        
        queue = [root]
        visited = set()
        
        while queue:
            unit = queue.pop(0)
            
            # Avoid cycles and re-processing
            # Some units might not have a path, so we handle that.
            try:
                unit_path = unit.getPath()
                if unit_path and unit_path in visited:
                    continue
                if unit_path:
                    visited.add(unit_path)
            except:
                # Fallback for units without getPath or other issues
                pass


            # Check if this unit is the one we are looking for
            if unit.getName() == name:
                print("Found a matching unit: %s" % name)
                return unit

            # If it's a composite unit, add its children to the queue
            if hasattr(unit, 'getChildren') and unit.getChildren():
                queue.extend(unit.getChildren())
        
        print("Could not find a unit with name: %s" % name)
        return None

    def inspect_object(self, obj, description):
        """Prints the attributes and methods of a given object."""
        if not obj:
            print("Object for '%s' is None, cannot inspect." % description)
            return
            
        print("\n--- Inspecting %s ---" % description)
        print("Object Type: %s" % obj.getClass())
        print("----------------------------------------------------")

        # Using introspection to get all members
        members = sorted(dir(obj))
        for member_name in members:
            # Skip private/special members for clarity
            if member_name.startswith('__'):
                continue
            
            try:
                member = getattr(obj, member_name)
                # Distinguish between methods and properties
                if callable(member):
                    print("  - %s()  [Method]" % member_name)
                else:
                    # It's a property/attribute
                    print("  - %s   [Property]" % member_name)
            except Exception as e:
                # Some attributes might not be accessible
                print("  - %s   [Error inspecting: %s]" % (member_name, e))
