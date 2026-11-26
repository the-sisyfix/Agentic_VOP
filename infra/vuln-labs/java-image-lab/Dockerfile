# Intentionally outdated Java runtime environment
# Tomcat 9.0.30 + OpenJDK 8 on Debian Buster — has JDK CVEs, Tomcat CVEs,
# and Debian OS-level CVEs baked into the base image layers.
# No apt-get needed — Debian Buster repos are EOL and unavailable.
FROM tomcat:9.0.30-jdk8-openjdk

# Deploy a placeholder webapp
RUN mkdir -p /usr/local/tomcat/webapps/ROOT
RUN echo '<html><body><h1>Vulnerable Java App</h1></body></html>' > /usr/local/tomcat/webapps/ROOT/index.html

# VULN: Running as root (no USER instruction)
# VULN: No HEALTHCHECK defined
EXPOSE 8080
CMD ["catalina.sh", "run"]
