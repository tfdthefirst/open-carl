import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.decompiler.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.*;
import java.util.*;

public class apply_names extends GhidraScript {
    String sanitize(String n){
        n = n.replace("::","__").replace(".","_");
        n = n.replaceAll("[^A-Za-z0-9_]","_");
        if (n.length() > 200) n = n.substring(0,200);
        return n;
    }
    boolean isGame(String n){
        return n.startsWith("ImpactLab") || n.startsWith("Carl")
            || n.startsWith("__Generated") || n.startsWith("Unity.Scripting");
    }
    public void run() throws Exception {
        String mapPath = System.getenv("MAPFILE");
        if (mapPath == null) mapPath = "/home/battledoge/Games/open-carl/recovered/methods.map";
        String outDir = System.getenv("DECOMP_OUT");
        if (outDir == null) outDir = "/home/battledoge/Games/open-carl/recovered/decompiled";

        Address base = currentProgram.getImageBase();
        FunctionManager fm = currentProgram.getFunctionManager();

        List<Long> rvas = new ArrayList<>();
        List<String> names = new ArrayList<>();
        BufferedReader br = new BufferedReader(new FileReader(mapPath));
        String line;
        while ((line = br.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] p = line.split("\t", 2);
            if (p.length != 2) continue;
            String r = p[0].startsWith("0x") ? p[0].substring(2) : p[0];
            try { rvas.add(Long.parseLong(r, 16)); names.add(p[1]); }
            catch (NumberFormatException e) {}
        }
        br.close();
        println("loaded " + rvas.size() + " map entries");

        int named = 0, created = 0;
        for (int i = 0; i < rvas.size(); i++) {
            Address a = base.add(rvas.get(i));
            Function f = fm.getFunctionAt(a);
            if (f == null) {
                try { f = createFunction(a, null); if (f != null) created++; }
                catch (Exception e) {}
            }
            if (f != null) {
                try { f.setName(sanitize(names.get(i)), SourceType.USER_DEFINED); named++; }
                catch (Exception e) {}
            }
        }
        println("named=" + named + " created=" + created);

        new File(outDir).mkdirs();
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        PrintWriter pw = new PrintWriter(new FileWriter(outDir + "/game_decompiled.c"));
        pw.println("// Project C.A.R.L. decompiled game code (Ghidra via runtime RVAs)\n");
        int done = 0, total = 0;
        for (int i = 0; i < rvas.size(); i++) if (isGame(names.get(i))) total++;
        println("decompiling " + total + " game-code functions...");
        for (int i = 0; i < rvas.size(); i++) {
            String nm = names.get(i);
            if (!isGame(nm)) continue;
            Address a = base.add(rvas.get(i));
            Function f = fm.getFunctionAt(a);
            if (f == null) continue;
            try {
                DecompileResults r = di.decompileFunction(f, 45, mon);
                if (r != null && r.decompileCompleted()) {
                    pw.println("// ==== " + nm + "  @0x" + Long.toHexString(rvas.get(i)) + " ====");
                    pw.println(r.getDecompiledFunction().getC());
                    pw.println();
                    done++;
                    if (done % 500 == 0) { pw.flush(); println("  decompiled " + done + "/" + total); }
                }
            } catch (Exception e) {}
        }
        pw.close();
        println("DECOMPILE DONE: " + done + " functions -> " + outDir + "/game_decompiled.c");
    }
}
