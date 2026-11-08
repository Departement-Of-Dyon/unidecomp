// ExportDecompiled.java — Ghidra headless post-analysis script for UniDecomp.
// Decompiles every function in the imported program and writes C pseudocode.
// Usage (via analyzeHeadless): -postScript ExportDecompiled.java <output.c>
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

import java.io.FileWriter;
import java.io.PrintWriter;

public class ExportDecompiled extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "decompiled.c";

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);

        PrintWriter w = new PrintWriter(new FileWriter(outPath));
        w.println("// Decompiled by Ghidra via UniDecomp");
        w.println("// Program: " + currentProgram.getName());
        w.println("// Language: " + currentProgram.getLanguageID());
        w.println();

        FunctionManager fm = currentProgram.getFunctionManager();
        int ok = 0, fail = 0;
        for (Function f : fm.getFunctions(true)) {
            if (monitor.isCancelled()) break;
            w.println("// ===== " + f.getName() + " @ " + f.getEntryPoint() + " =====");
            DecompileResults r = ifc.decompileFunction(f, 60, monitor);
            if (r != null && r.decompileCompleted()) {
                w.println(r.getDecompiledFunction().getC());
                ok++;
            } else {
                w.println("/* decompile failed: "
                        + (r != null ? r.getErrorMessage() : "no result") + " */");
                fail++;
            }
            w.println();
        }
        w.close();
        println("ExportDecompiled: " + ok + " functions decompiled, " + fail + " failed -> " + outPath);
    }
}
