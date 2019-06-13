#!/bin/sh
# Script to install OpenDistro + ELK + WAZUH in a CentOS 7 box
# This script is to short the process of installation, for better reference check OD, ELK and Wazuh Projects Documentations
#################################################################################################################
# My server have a security baseline (Hardening)
# And is joined to a domain
#################################################
passwd
mkdir $HOME/certs
# I use my own certificate for SSL Services, OD bring certs "kirk...", it works well, but i use my owns.
$HOME/certs/ca_cert.pem
$HOME/certs/client_cert.pem
$HOME/certs/client_cert.key
curl https://d3g5vo6xdbdb9a.cloudfront.net/yum/opendistroforelasticsearch-artifacts.repo -o /etc/yum.repos.d/opendistroforelasticsearch-artifacts.repo
yum install -y java-1.8.0-openjdk-devel unzip
yum install -y opendistroforelasticsearch opendistroforelasticsearch-kibana
ln -s /usr/lib/jvm/java-1.8.0/lib/tools.jar /usr/share/elasticsearch/lib/
systemctl daemon-reload
systemctl enable elasticsearch.service
systemctl enable kibana.service
curl -s https://raw.githubusercontent.com/tuxtter/OpenDistro-Wazuh/master/config.yml > /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/config.yml
cp $HOME/certs/ca_cert.pem /etc/elasticsearch/ca_cert.pem
cp $HOME/certs/client_cert.pem /etc/elasticsearch/client_cert.pem
cp $HOME/certs/client_cert.key /etc/elasticsearch/client_cert.key
#Note: Certs name must match with certs configured in elasticsearch.yml
curl -s https://raw.githubusercontent.com/tuxtter/OpenDistro-Wazuh/master/elasticsearch.yml > /etc/elasticsearch/elasticsearch.yml
chown elasticsearch:elasticsearch /etc/elasticsearch/ca_cert.pem
chown elasticsearch:elasticsearch /etc/elasticsearch/client_cert.pem
chown elasticsearch:elasticsearch /etc/elasticsearch/client_cert.key
# I link index default path "/var/lib/elasticsearch" to a bigger partition, in this case "/home", remember CentOS was hardened
mkdir -p /home/elasticsearch/elk-host/elk-data
rm -rf /var/lib/elasticsearch
ln -s /home/elasticsearch/elk-host/elk-data /var/lib/elasticsearch
chown elasticsearch:elasticsearch -R /home/elasticsearch
# Opendistro requires /tmp be mounted with exec permisions, this is not recommended. So you must create a tmp directory. I dont know XD, this works for me. And my hardening remains unmodified.
# Crear directorio tmp para elk
mkdir /home/elasticsearch/tmpelk/
chown -R elasticsearch:elasticsearch /home/elasticsearch/tmpelk/
sed -i '$ a ES_TMPDIR=/home/elasticsearch/tmpelk' /etc/sysconfig/elasticsearch
sed -i '/^metrics-db-file-prefix-path =/ c metrics-db-file-prefix-path = /home/elasticsearch/tmpelk/metricsdb_' /usr/share/elasticsearch/plugins/opendistro_performance_analyzer/pa_config/performance-analyzer.properties
sed -i s/'^PA_AGENT_JAVA_OPTS="'/'PA_AGENT_JAVA_OPTS=" -Djava.io.tmpdir=\/home\/elasticsearch\/tmpelk '/ /usr/share/elasticsearch/bin/performance-analyzer-agent-cli
sed -i s/'java'/'java -Djava.io.tmpdir=\/home\/elasticsearch\/tmpelk '/ /usr/share/elasticsearch/plugins/opendistro_performance_analyzer/pa_bin/performance-analyzer-agent
# Install requirements for OD perftop dashboards
yum -y  install epel-release
yum -y install supervisor
curl -s https://raw.githubusercontent.com/tuxtter/OpenDistro-Wazuh/master/kibana.yml > /etc/kibana/kibana.yml
sed -i "$ a 127.0.0.1 elk01.tuxtter.net" /etc/hosts
#Logstash
yum -y install logstash
systemctl daemon-reload
systemctl enable logstash.service
sed -i '/^#-Djava.io.tmpdir=$HOME/ c -Djava.io.tmpdir=/usr/share/logstash/tmp' /etc/logstash/jvm.options
mkdir /usr/share/logstash/tmp
chown logstash:logstash -R /usr/share/logstash/tmp
cp /etc/elasticsearch/client_cert.pem /etc/logstash/
chown logstash:logstash /etc/logstash/client_cert.pem
/usr/share/logstash/bin/logstash-plugin install logstash-output-slack
cd /usr/share/logstash/vendor/bundle/jruby/2.5.0/specifications/
chown logstash:logstash rest-client-1.8.0.gemspec netrc-0.11.0.gemspec logstash-output-slack-2.1.1.gemspec
cd ../gems/
chown -R logstash:logstash rest-client-1.8.0 netrc-0.11.0 logstash-output-slack-2.1.1
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/opendistroforelasticsearch-artifacts.repo
yum -y install httpd mod_ssl openssl
systemctl enable httpd.service
mkdir /etc/httpd/ssl
cp /etc/elasticsearch/client_cert.pem /etc/httpd/ssl/
cp /etc/elasticsearch/client_cert.key /etc/httpd/ssl/
sed -i "/^SSLCertificateFile/ c SSLCertificateFile '/etc/httpd/ssl/client_cert.pem'" /etc/httpd/conf.d/ssl.conf
sed -i "/^SSLCertificateKeyFile/ c SSLCertificateKeyFile '/etc/httpd/ssl/client_cert.key'" /etc/httpd/conf.d/ssl.conf
firewall-cmd --permanent --add-port=443/tcp
firewall-cmd --add-port=443/tcp
setsebool -P httpd_can_network_connect 1
curl -s https://raw.githubusercontent.com/tuxtter/OpenDistro-Wazuh/master/kibana.conf > /etc/httpd/conf.d/kibana.conf
sed -i "/^  SSLCertificateFile/ c SSLCertificateFile '/etc/httpd/ssl/client_cert.pem'" /etc/httpd/conf.d/kibana.conf
sed -i "/^  SSLCertificateKeyFile/ c SSLCertificateKeyFile '/etc/httpd/ssl/client_cert.key'" /etc/httpd/conf.d/kibana.conf
service httpd restart
sed -i 's/-Xms1g/-Xms32g/g' /etc/elasticsearch/jvm.options
sed -i 's/-Xmx1g/-Xmx32g/g' /etc/elasticsearch/jvm.options
cat > /etc/yum.repos.d/wazuh.repo <<\EOF
[wazuh_repo]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/3.x/yum/
protect=1
EOF
yum -y install wazuh-manager
curl --silent --location https://rpm.nodesource.com/setup_8.x | bash -
yum install -y nodejs
yum -y install wazuh-api
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo
#Install the compatible plugin version with OpenDistro at the moment: 6.7.1
/usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-3.9.0_6.7.1.zip
curl -so /etc/logstash/conf.d/01-wazuh.conf https://raw.githubusercontent.com/wazuh/wazuh/master/extensions/logstash/6.x/01-wazuh-local.conf
chown logstash:logstash /etc/logstash/conf.d/01-wazuh.conf
usermod -a -G ossec logstash
systemctl daemon-reload
firewall-cmd --permanent --add-port=1515/tcp
firewall-cmd --permanent --add-port=1514/udp
firewall-cmd --reload
# Performance Analyzer
mkdir $HOME/perf-top
cd $HOME/perf-top
curl https://d3g5vo6xdbdb9a.cloudfront.net/downloads/perftop/perf-top-0.7.0.0-LINUX.zip -o $HOME/perf-top/perf-top-0.7.0.0-LINUX.zip
unzip $HOME/perf-top/perf-top-0.7.0.0-LINUX.zip
# To start using OD + Wazuh, you must configure the right roles and permissions to create, manipulate and explore the cluster and indexes.
# If you have a localhost installation, the next config works. But if you have a production server, you must be more specific with the roles and permissions.
# These are some of the permissions I found necessary to be configured (check your elk logs for more index permissions).
##User: kibanaserver
#
#Index 			Permission
#.wazuh indices:admin/get
#.wazuh indices:admin/create
#.wazuh indices:data/write/update
#.wazuh indices:admin/settings/update
#.wazuh-version indices:data/read/get
#.wazuh-version indices:admin/create
#.wazuh-version indices:data/write/update
#.wazuh-version indices:data/write/index
#.wazuh-version indices:data/read/search
#.wazuh-version indices:data/write/bulk[s]
#wazuh-monitoring-* indices:admin/get
#wazuh-monitoring-* indices:data/read/field_caps
#wazuh-monitoring-* indices:data/read/field_caps[index]
#wazuh-monitoring-* indices:admin/settings/update
#wazuh-monitoring-* indices:data/write/bulk[s]
#wazuh-monitoring-* indices:admin/mapping/put
#wazuh-alerts-* indices:data/read/field_caps
#.kibana_1 indices:data/read/get
#.kibana_1 indices:data/read/search
#
#User: logstash
#
#Index 			Permission
#wazuh-alerts-* CRUD
#wazuh-alerts-* create_index

#Anyway, with this config, you can workaround that XD :P, exec only once
echo "
full_access:
  readonly: false
  cluster:
    - UNLIMITED
  indices:
    '*':
      '*':
        - UNLIMITED
  tenants:
    admin_tenant: RW" >> /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles.yml
echo "
full_access:
  readonly: false
  backendroles:
    - logstash
    - kibanauser
    - admin
  users:
    - kibanaserver" >> /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles_mapping.yml
# Set the password for Wazuh API
node /var/ossec/api/configuration/auth/htpasswd -c /var/ossec/api/configuration/auth/user manager
# Set the password for OpenDistro admin user
sh /usr/share/elasticsearch/plugins/opendistro_security/tools/hash.sh
# Replace default password for admin user
vi /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml
# Set password for auto agent register
vi /var/ossec/etc/authd.pass
vi /var/ossec/etc/ossec.conf
	-- <use_password>no</use_password>
	++ <use_password>yes</use_password>
# Modify wazuh config file in logstash to match as follows in output section
vi /etc/logstash/conf.d/01-wazuh.conf
hosts => ["https://elk01.tuxtter.net:9200"]
ssl => true
cacert => '/etc/logstash/client_cert.pem'
index => "wazuh-alerts-3.x-%{+YYYY.MM.dd}"
user => "logstash"
password => "logstash"
document_type => "wazuh"
#Reboot server
reboot
# Check cluster health
curl -XGET 'https://localhost:9200/_cluster/health?pretty=true' --insecure -u admin:YOURADMINPASSWORD
# In case your ELK is in Yellow, may be the reason is this ... anyway check your logs.
curl -k -XPUT 'https://localhost:9200/*/_settings?pretty' -H 'Content-Type: application/json' -d '{"number_of_replicas": 0}' -u admin:YOURADMINPASSWORD
curl -k -s https://raw.githubusercontent.com/wazuh/wazuh/master/extensions/elasticsearch/6.x/wazuh-template.json | curl -k -XPUT 'https://localhost:9200/_template/wazuh' -H 'Content-Type: application/json' -d @- -u admin:YOURADMINPASSWORD
# Kibana stop/start commands
systemctl stop kibana.service
service kibana stop
service kibana start
# Extra useful commands
# Reload OD config files
#/bin/sh /usr/share/elasticsearch/plugins/opendistro_security/tools/securityadmin.sh -cd /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/ -icl -nhnv -cacert /etc/elasticsearch/ca_cert.pem -cert /etc/elasticsearch/client_cert.pem -key /etc/elasticsearch/client_cert.key
# Test wazuh config in logstash
#/usr/share/logstash/bin/logstash -t -f /etc/logstash/conf.d/01-wazuh-local.conf
# To view performance dashboard
#$HOME/perf-top/perf-top-linux --dashboard $HOME/perf-top/dashboards/ClusterOverview.json
# Verify listening ports
#netstat -tapn | grep LISTEN
#
# In case you dont want to create an extra tmp directory for OD, you must remount /tmp partition with exec option
#mount -o remount,exec /tmp
