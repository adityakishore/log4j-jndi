/* Copyright (c) 2021 & onwards. MapR Tech, Inc., All rights reserved */
package com.hpe.edf;

import java.io.File;
import java.io.FileFilter;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class Log4jJndi {
  private static boolean debug = false;

  private static boolean print = false;

  private static boolean delete = false;

  private static String appBaseDir = null;

  private static String searchClass = "org/apache/logging/log4j/core/lookup/JndiLookup.class";

  public static void main(final String[] args) {
    if (args == null || args.length == 0) {
      usage();
    }

    try {
      for (int i = 0; i < args.length; i++) {
        switch (args[i]) {
        case "--base":
          appBaseDir = getStrArgVal(args[i], ++i, args);
          break;
        case "--class":
          searchClass = getStrArgVal(args[i], ++i, args);
          break;
        case "--debug":
          debug = true;
          break;
        case "--print":
          print = true;
          break;
        case "--delete":
          delete = true;
          break;
        case "--help":
        default:
          usage();
        }
      }

      if (appBaseDir == null) {
        System.err.println("Base application directory is not specified.");
        usage();
      }

      if (print && delete) {
        System.err.println("Only one of '--print' or '--delete' can be specified.");
        usage();
      }

      int jarCount = run();
      System.exit(jarCount);
    } catch (Exception e) {
      System.err.println(e.getMessage());
      if (debug) {
        e.printStackTrace();
      }
    }
  }

  private static int run() throws Exception {
    int jarCount = 0;
    final List<URL> javaArchives = new ArrayList<URL>();
    findAllArchives(new File(appBaseDir), javaArchives);

    final URL[] urls = javaArchives.toArray(new URL[0]);
    final URLClassLoader classLoader = new URLClassLoader(urls);
    final Enumeration<URL> resUrls = classLoader.getResources(searchClass);
    while (resUrls.hasMoreElements()) {
      final URL jndiLookupUrl = resUrls.nextElement();
      if (jndiLookupUrl.getProtocol().equals("jar")) {
        jarCount++;
        final String jndiLookupFullURL = jndiLookupUrl.getPath();
        final int beginIndex = jndiLookupFullURL.indexOf(':') + 1;
        final int endIndex = jndiLookupFullURL.lastIndexOf('!');
        final String jndiLookupJarPath = jndiLookupFullURL.substring(beginIndex, endIndex);
        final String deleteCmd = String.format("zip -q -d %s %s", jndiLookupJarPath, searchClass);
        if (print) {
          System.out.println(deleteCmd);
        } else if (delete) {
          System.out.printf("Deleting JndiLookup from '%s' ... ", jndiLookupJarPath);
          int exitCode = Runtime.getRuntime().exec(deleteCmd).waitFor();
          System.out.println(exitCode == 0 ? "succeeded." : "failed!");
        } else {
          System.out.println(jndiLookupFullURL);
        }
      }
    }
    classLoader.close();
    return jarCount;
  }

  private static void findAllArchives(final File dir, final List<URL> javaArchives) {
    if (!dir.isDirectory()) {
      return;
    }

    final File[] dirs = dir.listFiles(new FileFilter() {
      public boolean accept(final File file) {
        if (file.isDirectory()) {
          return true;
        } else {
          final String filename = file.getName();
          final int extBegins = filename.lastIndexOf(".") + 1;
          if (extBegins > 0) {
            final String ext = filename.substring(extBegins).toLowerCase();
            URL url;
            switch (ext) {
            case "zip":
            case "jar":
            case "war":
              try {
                url = file.toURI().toURL();
                javaArchives.add(url);
              } catch (final MalformedURLException e) {
              }
              break;
            }
          }
          return false;
        }
      }
    });

    for (final File dir0 : dirs) {
      findAllArchives(dir0, javaArchives);
    }

  }

  private static void usage() {
    System.err.println("Usage: ");
    System.err.println("java -jar com.hpe.edf.Log4jJndi --base <base folder to scan> [--debug] [--print|--delete] [--class <classname>]");
    System.exit(22);
  }

  private static String getStrArgVal(final String argName, int nextIdx, final String[] args) {
    if (nextIdx < args.length && !args[nextIdx].startsWith("-")) {
      return args[nextIdx];
    } else {
      throw new IllegalArgumentException("Missing or invalid argument for the parameter '" + argName + "'");
    }
  }

}
