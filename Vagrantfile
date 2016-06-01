# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/trusty64"

  # Enable provisioning with a shell script. Additional provisioners such as
  # Puppet, Chef, Ansible, Salt, and Docker are also available. Please see the
  # documentation for more information about their specific syntax and use.
  config.vm.provision "shell", inline: <<-SHELL
    sudo apt-get update
    sudo apt-get install -y build-essential autotools-dev autoconf libtool pkg-config git xutils-dev gengetopt help2man swig python-dev openjdk-7-jdk openjdk-7-jre-headless ruby-dev golang-go gccgo
    ln -s /vagrant /home/vagrant/openpace
    cd /home/vagrant/openpace
    autoreconf -vis
    ./configure --enable-openssl-install --enable-python --enable-java --enable-ruby --enable-go GCCGOFLAGS="-static-libgcc -static-libgo"
    make
  SHELL
end
