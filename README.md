# log4j-jndi (CVE-2021-44228)

A utility class to print/delete the JndiLookup class in Java archives within an application installation folder.

**Important:** This is an experimental code. Use it at your own risk.

## To Build
```
mvn install
```

## To Run
```
java -jar target/log4j-jndi-fix-1.0.jar --base <base_directory_of_app>
```

This will scan the application installation directory recursively and prints the URL of JndiLookup class within the archives.

E.g.
```
[admn@vm162052 log4j-jndi]$ sudo java -jar target/log4j-jndi-fix-1.0.jar --base /usr/share/elasticsearch
file:/usr/share/elasticsearch/bin/elasticsearch-sql-cli-6.8.20.jar!/org/apache/logging/log4j/core/lookup/JndiLookup.class
file:/usr/share/elasticsearch/lib/log4j-core-2.11.1.jar!/org/apache/logging/log4j/core/lookup/JndiLookup.class
```

Use `--print` option on the command line for the tool to print the command to delete the classes.

E.g.
```
[admn@vm162052 log4j-jndi]$ sudo java -jar target/log4j-jndi-fix-1.0.jar --base /usr/share/elasticsearch --print
zip -q -d /usr/share/elasticsearch/bin/elasticsearch-sql-cli-6.8.20.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
zip -q -d /usr/share/elasticsearch/lib/log4j-core-2.11.1.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
```

Use `--delete` option on the command line for the tool to delete the classes by invoking the command directly.

E.g.
```
[admn@vm162052 log4j-jndi]$ sudo java -jar target/log4j-jndi-fix-1.0.jar --base /usr/share/elasticsearch --delete
Deleting JndiLookup from '/usr/share/elasticsearch/bin/elasticsearch-sql-cli-6.8.20.jar' ... succeeded.
Deleting JndiLookup from '/usr/share/elasticsearch/lib/log4j-core-2.11.1.jar' ... succeeded.
```
