/*
 * Copyright 2016, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.jf.baksmali;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.beust.jcommander.ParametersDelegate;
import com.google.common.collect.Lists;
import org.jf.baksmali.AnalysisArguments.CheckPackagePrivateArgument;
import org.jf.dexlib2.analysis.CustomInlineMethodResolver;
import org.jf.dexlib2.analysis.InlineMethodResolver;
import org.jf.dexlib2.dexbacked.DexBackedOdexFile;
import org.jf.util.jcommander.ExtendedParameter;
import org.jf.util.jcommander.ExtendedParameters;

import javax.annotation.Nonnull;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Parameters(commandDescription = "Deodexes an odex/oat file")
@ExtendedParameters(
        commandName = "deodex",
        commandAliases = { "de", "x" })
public class DeodexCommand extends DisassembleCommand {

    @ParametersDelegate
    protected CheckPackagePrivateArgument checkPackagePrivateArgument = new CheckPackagePrivateArgument();

    @Parameter(names = {"--inline-table", "--inline", "--it"},
            description = "Specify a file containing a custom inline method table to use. See the " +
                    "\"deodexerant\" tool in the smali github repository to dump the inline method table from a " +
                    "device that uses dalvik.")
    @ExtendedParameter(argumentNames = "file")
    private String inlineTable;

    public DeodexCommand(@Nonnull List<JCommander> commandAncestors) {
        super(commandAncestors);
    }

    @Override protected BaksmaliOptions getOptions() {
        BaksmaliOptions options = super.getOptions();

        options.deodex = true;

        if (dexFile instanceof DexBackedOdexFile) {
            if (inlineTable == null) {
                options.inlineResolver = InlineMethodResolver.createInlineMethodResolver(
                        ((DexBackedOdexFile)dexFile).getOdexVersion());
            } else {
                File inlineTableFile = new File(inlineTable);
                if (!inlineTableFile.exists()) {
                    System.err.println(String.format("Could not find file: %s", inlineTable));
                    System.exit(-1);
                }
                try {
                    options.inlineResolver = new CustomInlineMethodResolver(options.classPath, inlineTableFile);
                } catch (IOException ex) {
                    System.err.println(String.format("Error while reading file: %s", inlineTableFile));
                    ex.printStackTrace(System.err);
                    System.exit(-1);
                }
            }
        }

        return options;
    }

    @Override
    public void run() {
        if (help || inputList == null || inputList.isEmpty()) {
            usage();
            return;
        }

        if (inputList.size() > 1) {
            System.err.println("Too many files specified");
            usage();
            return;
        }

        String input = inputList.get(0);
        loadDexFile(input);

        File outputDirOrFile = new File(output);
        if (!outputDirOrFile.exists()) {
            if (outputDirOrFile.getName().endsWith(".dex")) {
                if (outputDirOrFile.getParentFile() != null && !outputDirOrFile.getParentFile().getName().endsWith(".apk") &&
                        !outputDirOrFile.getParentFile().getName().endsWith(".jar")) {
                    if (!outputDirOrFile.getParentFile().mkdirs()) {
                        System.err.println("Can't create the output directory " + output);
                        System.exit(-1);
                    }
                }
            } else {
                if (!outputDirOrFile.mkdirs()) {
                    System.err.println("Can't create the output directory " + output);
                    System.exit(-1);
                }
            }
        }

        if (analysisArguments.classPathDirectories == null || analysisArguments.classPathDirectories.isEmpty()) {
            analysisArguments.classPathDirectories = Lists.newArrayList(inputFile.getAbsoluteFile().getParent());
        }

        if (outputDirOrFile.exists() && outputDirOrFile.isDirectory()) {
            if (!Baksmali.disassembleDexFile(dexFile, outputDirOrFile, jobs, getOptions(), classes)) {
                System.exit(-1);
            }
        } else {
            FileSystem zipfs = null;
            Path outputZip = null;
            if ((outputDirOrFile.getParentFile() != null && (outputDirOrFile.getParentFile().getName().endsWith(".apk") ||
                    outputDirOrFile.getParentFile().getName().endsWith(".jar")) && outputDirOrFile.getParentFile().exists()) ||
                    (outputDirOrFile.getName().endsWith(".apk") || outputDirOrFile.getName().endsWith(".jar"))) {

                Map<String, String> env = new HashMap<>();
                env.put("create", "true");
                env.put("encoding", "UTF-8");
                // locate file system by using the syntax
                // defined in java.net.JarURLConnection
                URI uri = null;
                //System.out.println(uri.toString());
                try {

                    if (outputDirOrFile.getName().endsWith(".apk") || outputDirOrFile.getName().endsWith(".jar")) {
                        uri = URI.create("jar:" + outputDirOrFile.toURI());
                        zipfs = FileSystems.newFileSystem(uri, env);
                        System.out.println(zipfs.getPath("classes.dex"));
                        outputZip = zipfs.getPath("classes.dex");
                    } else {
                        uri = URI.create("jar:" + outputDirOrFile.getParentFile().toURI());
                        zipfs = FileSystems.newFileSystem(uri, env);
                        outputZip = zipfs.getPath(outputDirOrFile.getName());
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }

            try {
                if (outputZip != null) {
                    if (!Baksmali.DeoptimizeOdexFile(dexFile, outputZip, jobs, getOptions(), classes)) {
                        System.exit(-1);
                    }
                } else {
                    if (!Baksmali.DeoptimizeOdexFile(dexFile, outputDirOrFile, jobs, getOptions(), classes)) {
                        System.exit(-1);
                    }
                }
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if (zipfs != null && zipfs.isOpen()) {
                    try {
                        zipfs.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }

        }
    }

    @Override protected boolean shouldCheckPackagePrivateAccess() {
        return checkPackagePrivateArgument.checkPackagePrivateAccess;
    }

    @Override protected boolean needsClassPath() {
        return true;
    }
}
