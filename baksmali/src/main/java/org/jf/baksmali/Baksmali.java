/*
 * [The "BSD licence"]
 * Copyright (c) 2010 Ben Gruver (JesusFreke)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.jf.baksmali;

import com.google.common.collect.Lists;
import com.google.common.collect.Ordering;
import org.antlr.runtime.CommonTokenStream;
import org.antlr.runtime.TokenSource;
import org.antlr.runtime.tree.CommonTree;
import org.antlr.runtime.tree.CommonTreeNodeStream;
import org.jf.baksmali.Adaptors.ClassDefinition;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.writer.builder.DexBuilder;
import org.jf.dexlib2.writer.io.FileDataStore;
import org.jf.smali.LexerErrorInterface;
import org.jf.smali.smaliFlexLexer;
import org.jf.smali.smaliParser;
import org.jf.smali.smaliTreeWalker;
import org.jf.util.ClassFileNameHandler;
import org.jf.util.IndentingWriter;

import javax.annotation.Nullable;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.*;

public class Baksmali {
    public static boolean disassembleDexFile(DexFile dexFile, File outputDir, int jobs, final BaksmaliOptions options) {
        return disassembleDexFile(dexFile, outputDir, jobs, options, null);
    }

    public static boolean disassembleDexFile(DexFile dexFile, File outputDir, int jobs, final BaksmaliOptions options,
                                             @Nullable List<String> classes) {
        //sort the classes, so that if we're on a case-insensitive file system and need to handle classes with file
        //name collisions, then we'll use the same name for each class, if the dex file goes through multiple
        //baksmali/smali cycles for some reason. If a class with a colliding name is added or removed, the filenames
        //may still change of course
        List<? extends ClassDef> classDefs = Ordering.natural().sortedCopy(dexFile.getClasses());

        final ClassFileNameHandler fileNameHandler = new ClassFileNameHandler(outputDir, ".smali");

        ExecutorService executor = Executors.newFixedThreadPool(jobs);
        List<Future<Boolean>> tasks = Lists.newArrayList();

        Set<String> classSet = null;
        if (classes != null) {
            classSet = new HashSet<String>(classes);
        }

        for (final ClassDef classDef : classDefs) {
            if (classSet != null && !classSet.contains(classDef.getType())) {
                continue;
            }
            tasks.add(executor.submit(new Callable<Boolean>() {
                @Override
                public Boolean call() throws Exception {
                    return disassembleClass(classDef, fileNameHandler, options);
                }
            }));
        }

        boolean errorOccurred = false;
        try {
            for (Future<Boolean> task : tasks) {
                while (true) {
                    try {
                        if (!task.get()) {
                            errorOccurred = true;
                        }
                    } catch (InterruptedException ex) {
                        continue;
                    } catch (ExecutionException ex) {
                        throw new RuntimeException(ex);
                    }
                    break;
                }
            }
        } finally {
            executor.shutdown();
        }
        return !errorOccurred;
    }

    private static boolean disassembleClass(ClassDef classDef, ClassFileNameHandler fileNameHandler,
                                            BaksmaliOptions options) {
        /**
         * The path for the disassembly file is based on the package name
         * The class descriptor will look something like:
         * Ljava/lang/Object;
         * Where the there is leading 'L' and a trailing ';', and the parts of the
         * package name are separated by '/'
         */
        String classDescriptor = classDef.getType();

        //validate that the descriptor is formatted like we expect
        if (classDescriptor.charAt(0) != 'L' ||
                classDescriptor.charAt(classDescriptor.length() - 1) != ';') {
            System.err.println("Unrecognized class descriptor - " + classDescriptor + " - skipping class");
            return false;
        }

        File smaliFile = fileNameHandler.getUniqueFilenameForClass(classDescriptor);

        //create and initialize the top level string template
        ClassDefinition classDefinition = new ClassDefinition(options, classDef);

        //write the disassembly
        Writer writer = null;
        try {
            File smaliParent = smaliFile.getParentFile();
            if (!smaliParent.exists()) {
                if (!smaliParent.mkdirs()) {
                    // check again, it's likely it was created in a different thread
                    if (!smaliParent.exists()) {
                        System.err.println("Unable to create directory " + smaliParent.toString() + " - skipping class");
                        return false;
                    }
                }
            }

            if (!smaliFile.exists()) {
                if (!smaliFile.createNewFile()) {
                    System.err.println("Unable to create file " + smaliFile.toString() + " - skipping class");
                    return false;
                }
            }

            BufferedWriter bufWriter = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(smaliFile), "UTF8"));

            writer = new IndentingWriter(bufWriter);
            classDefinition.writeTo((IndentingWriter) writer);

        } catch (Exception ex) {
            System.err.println("\n\nError occurred while disassembling class " + classDescriptor.replace('/', '.') + " - skipping class");
            ex.printStackTrace();
            // noinspection ResultOfMethodCallIgnored
            smaliFile.delete();
            return false;
        } finally {
            if (writer != null) {
                try {
                    writer.close();
                } catch (Throwable ex) {
                    System.err.println("\n\nError occurred while closing file " + smaliFile.toString());
                    ex.printStackTrace();
                }
            }
        }
        return true;
    }

    public static boolean DeoptimizeOdexFile(DexFile dexFile, Path outputFile, int jobs, final BaksmaliOptions options,
                                             @Nullable List<String> classes) throws Exception {
        File tmp = File.createTempFile("smali",".dex");
        if (!Baksmali.DeoptimizeOdexFile(dexFile, tmp, jobs, options, classes)) {
            if (tmp.exists()){
                tmp.delete();
            }
            return false;
        }
        Files.copy(tmp.toPath(), outputFile, StandardCopyOption.REPLACE_EXISTING);
        if (tmp.exists()){
            tmp.delete();
        }
        return true;
    }


    public static boolean DeoptimizeOdexFile(DexFile dexFile, File outputFile, int jobs, final BaksmaliOptions options,
                                             @Nullable List<String> classes) throws Exception {

        //sort the classes, so that if we're on a case-insensitive file system and need to handle classes with file
        //name collisions, then we'll use the same name for each class, if the dex file goes through multiple
        //baksmali/smali cycles for some reason. If a class with a colliding name is added or removed, the filenames
        //may still change of course
        List<? extends ClassDef> classDefs = Ordering.natural().sortedCopy(dexFile.getClasses());

        ExecutorService executor = Executors.newFixedThreadPool(jobs);
        List<Future<Boolean>> tasks = Lists.newArrayList();

        final DexBuilder dexBuilder = new DexBuilder(Opcodes.forApi(options.apiLevel));

        Set<String> classSet = null;
        if (classes != null) {
            classSet = new HashSet<String>(classes);
        }

        for (final ClassDef classDef : classDefs) {
            if (classSet != null && !classSet.contains(classDef.getType())) {
                continue;
            }
            tasks.add(executor.submit(new Callable<Boolean>() {
                @Override
                public Boolean call() throws Exception {
                    return assembleSmaliFile(disassembleClass(classDef, options) , dexBuilder, options);
                }
            }));
        }

        boolean errorOccurred = false;
        try {
            for (Future<Boolean> task : tasks) {
                while (true) {
                    try {
                        if (!task.get()) {
                            errorOccurred = true;
                        }
                    } catch (InterruptedException ex) {
                        continue;
                    } catch (ExecutionException ex) {
                        throw new RuntimeException(ex);
                    }
                    break;
                }
            }
        } finally {
            executor.shutdown();
        }

        if (errorOccurred) {
            return false;
        }

        dexBuilder.writeTo(new FileDataStore(outputFile));

        return true;
    }

    private static byte[] disassembleClass(ClassDef classDef, BaksmaliOptions options) {
        /**
         * The path for the disassembly file is based on the package name
         * The class descriptor will look something like:
         * Ljava/lang/Object;
         * Where the there is leading 'L' and a trailing ';', and the parts of the
         * package name are separated by '/'
         */
        String classDescriptor = classDef.getType();

        //validate that the descriptor is formatted like we expect
        if (classDescriptor.charAt(0) != 'L' ||
                classDescriptor.charAt(classDescriptor.length() - 1) != ';') {
            System.err.println("Unrecognized class descriptor - " + classDescriptor + " - skipping class");
            return null;
        }
        //create and initialize the top level string template
        ClassDefinition classDefinition = new ClassDefinition(options, classDef);

        //write the disassembly
        Writer writer = null;
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            OutputStreamWriter outWriter = new OutputStreamWriter(bos, "UTF8");
            writer = new IndentingWriter(outWriter);
            classDefinition.writeTo((IndentingWriter) writer);
            writer.flush();
            byte[] arr = bos.toByteArray();
            bos.close();
            return arr;
        } catch (Exception ex) {
            System.err.println("\n\nError occurred while disassembling class " + classDescriptor.replace('/', '.') + " - skipping class");
            ex.printStackTrace();
            // noinspection ResultOfMethodCallIgnored
            return null;
        } finally {
            if (writer != null) {
                try {
                    writer.close();
                } catch (Throwable ex) {
                    System.err.println("\n\nError occurred while closing output ");
                    ex.printStackTrace();
                }
            }
        }
    }

    private static boolean assembleSmaliFile(byte[] bytes, DexBuilder dexBuilder, BaksmaliOptions options)
            throws Exception {
        ByteArrayInputStream bis = null;
        try {
            bis = new ByteArrayInputStream(bytes);
            InputStreamReader reader = new InputStreamReader(bis, "UTF-8");

            LexerErrorInterface lexer = new smaliFlexLexer(reader);
            CommonTokenStream tokens = new CommonTokenStream((TokenSource) lexer);


            smaliParser parser = new smaliParser(tokens);
            parser.setApiLevel(options.apiLevel);

            smaliParser.smali_file_return result = parser.smali_file();

            if (parser.getNumberOfSyntaxErrors() > 0 || lexer.getNumberOfSyntaxErrors() > 0) {
                return false;
            }

            CommonTree t = result.getTree();

            CommonTreeNodeStream treeStream = new CommonTreeNodeStream(t);
            treeStream.setTokenStream(tokens);

            smaliTreeWalker dexGen = new smaliTreeWalker(treeStream);
            dexGen.setApiLevel(options.apiLevel);
            dexGen.setDexBuilder(dexBuilder);
            dexGen.smali_file();

            return dexGen.getNumberOfSyntaxErrors() == 0;
        } finally {
            if (bis != null) {
                bis.close();
            }
        }

    }
}
