// Synchronizes FLOSS-QS string attribution into Ghidra 12.0.3+
// @category FLOSS.QS
// @author Vikas

import java.nio.file.Files;
import java.nio.file.Paths;
import com.google.gson.*; 
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;

public class FlossQsLoader extends GhidraScript {
    @Override
    public void run() throws Exception {
        String jsonPath = "C:\\Users\\vikas\\Desktop\\flare-floss\\floss\\language\\go\\go_ghidra_map.json";
        
        try {
            String content = new String(Files.readAllBytes(Paths.get(jsonPath)));
            JsonArray data = JsonParser.parseString(content).getAsJsonArray();
            
            SymbolTable st = currentProgram.getSymbolTable();
            Namespace globalNs = currentProgram.getGlobalNamespace();
            Namespace ns = st.getOrCreateNameSpace(globalNs, "QS_Attribution", SourceType.USER_DEFINED);

            monitor.initialize(data.size());
            int count = 0;
            for (JsonElement e : data) {
                if (monitor.isCancelled()) break;
                JsonObject o = e.getAsJsonObject();
                Address addr = toAddr(o.get("va").getAsString());
                
                if (currentProgram.getMemory().contains(addr)) {
                    String str = o.get("string").getAsString();
                    String cat = o.has("category") ? o.get("category").getAsString() : "unknown";
                    
                    setPreComment(addr, "[QS] " + cat.toUpperCase() + ": " + str);
                    String prefix = (cat.equals("winapi")) ? "API_" : "STR_";
                    String label = prefix + str.replaceAll("[^a-zA-Z0-9]", "_");
                    
                    // Create and force primary for visibility
                    Symbol s = st.createLabel(addr, label.substring(0, Math.min(label.length(), 25)), ns, SourceType.USER_DEFINED);
                    if (s != null) s.setPrimary();
                }
                monitor.setProgress(++count);
            }
            currentProgram.flushEvents();
            println("Vikas's QS Sync Complete on Ghidra 12.0.3.");
        } catch (Exception ex) {
            printerr("ERROR: " + ex.getMessage());
        }
    }
}
