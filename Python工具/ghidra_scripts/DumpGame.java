// Export decompilation, function index, references, and loaded data blocks.
// @category StarrySky
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

public class DumpGame extends GhidraScript {
    private PrintWriter writer(File root, String name) throws Exception {
        return new PrintWriter(new OutputStreamWriter(new FileOutputStream(new File(root, name)), StandardCharsets.UTF_8));
    }
    public void run() throws Exception {
        File root = new File(getScriptArgs()[0]);
        root.mkdirs();
        File decompDir = new File(root, "decomp");
        decompDir.mkdirs();
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        try (PrintWriter meta = writer(root, "program.txt")) {
            meta.println("Program=" + currentProgram.getName());
            meta.println("Language=" + currentProgram.getLanguageID());
            meta.println("ImageBase=" + currentProgram.getImageBase());
            meta.println("Compiler=" + currentProgram.getCompilerSpec().getCompilerSpecID());
            for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
                meta.println(block.getName() + " " + block.getStart() + " " + block.getSize() + " X=" + block.isExecute());
                if (block.isInitialized() && !block.isExecute() && block.getSize() <= 4000000) {
                    byte[] data = new byte[(int)block.getSize()];
                    block.getBytes(block.getStart(), data);
                    Files.write(new File(root, "memory_" + block.getStart().toString().replace(':', '_') + ".bin").toPath(), data);
                }
            }
        }
        try (PrintWriter index = writer(root, "functions.tsv");
             PrintWriter all = writer(root, "all_functions.c");
             PrintWriter refs = writer(root, "references.tsv")) {
            index.println("address\tname\tsize\tdecompiled");
            refs.println("from\tto\ttype\tfunction");
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            int count = 0;
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                DecompileResults result = di.decompileFunction(f, 40, monitor);
                boolean ok = result.decompileCompleted();
                String code = ok ? result.getDecompiledFunction().getC() : "// FAILED " + result.getErrorMessage();
                String addr = f.getEntryPoint().toString();
                Files.writeString(new File(decompDir, "F_" + addr + ".c").toPath(), code, StandardCharsets.UTF_8);
                all.println("\n// ===== " + addr + " " + f.getName() + " =====\n" + code);
                index.println(addr + "\t" + f.getName() + "\t" + f.getBody().getNumAddresses() + "\t" + ok);
                InstructionIterator ins = currentProgram.getListing().getInstructions(f.getBody(), true);
                while (ins.hasNext()) {
                    Instruction instruction = ins.next();
                    for (Reference r : instruction.getReferencesFrom()) {
                        if (!r.getReferenceType().isFlow() || r.getReferenceType().isCall()) {
                            refs.println(r.getFromAddress() + "\t" + r.getToAddress() + "\t" + r.getReferenceType() + "\t" + addr);
                        }
                    }
                }
                if (++count % 100 == 0) println("Exported " + count + " functions");
            }
            println("DONE exported " + count + " functions");
        } finally { di.dispose(); }
    }
}
