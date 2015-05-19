## Mainten Active Directory membership 
## Nikolay Georgieff
## 

class ad_member(

  $rhel5_packages     = [ 'samba-common', 'krb5-workstation' ],
  $rhel6_packages     = [ 'samba-winbind', 'krb5-workstation' ],
  $winbind_user       = 'winbind',
  $winbind_password   = hiera('winbind_password'),
  $prod_domain        = 'WINDOWS_DOMAIN',
  $prod_realm         = 'FQDN.DOMAIN.COM',
  $prod_adserver      = '"ad1.domain.com ad2.domain.com"',
  $prod_sudoers       = '%WINDOWS_DOMAIN\\domain\ admins   ALL=(ALL)       ALL',
  $prod_admins_sid    = 'S-1-5-21-1989681264-694051721-1159422225-512',
  $dev_domain         = 'DEV_DOMAIN',
  $dev_realm          = 'DEV.DOMAIN.COMPANY.COM',
  $dev_adserver       = 'dad1.dev.companu.com',
  $dev_sudoers        = '%DEV_DOMAIN\\domain\ users		ALL=(ALL)       ALL',

)
{
  #validate_re($rhel5_packages, '^[a-zA-Z0-9_]+$')
  #validate_re($rhel6_packages, '^[a-zA-Z0-9_]+$')

# Set dependencies based on OS release version 
case $::operatingsystemrelease {
        /^5/: {
        $dependencies = $rhel5_packages
        $systemauth   = 'system-auth'
        $service      = 'smb'
  }
        /^6/: {
        $dependencies = $rhel6_packages
        $systemauth   = 'password-auth'
        $service      = 'winbind'
  }
}
## Environments
case $foreman_env {
  development: {
  $ad_domain = $dev_domain
  $realm     = $dev_realm
  $ad_server = $dev_adserver
  $sudoers   = $dev_sudoers
}
  testing: {
        $ad_domain = $prod_domain
        $realm     = $prod_realm
        $ad_server = $prod_adserver
        $sudoers   = $prod_sudoers
}
        qa: {
        $ad_domain = $prod_domain
        $realm     = $prod_realm
        $ad_server = $prod_adserver
        $sudoers   = $prod_sudoers
}
        production: {
        $ad_domain = $prod_domain
        $realm     = $prod_realm
        $ad_server = $prod_adserver
        $sudoers   = $prod_sudoers
}
}

#include resolv_conf

class { 'resolv_conf':
        domain     => $realm,
        search     => 'it.company.com sub1.company.com dpns.sun1.company.com dev.domain.company.com security.company.com',
        nameserver => ['8.8.8.8', '8.8.4.4'],
        before     => Class['ad-member'],
    }

## Install all dependencies
package { $dependencies:
        ensure   => installed
        }

augeas{ 'smb.conf' :
    context => '/files/etc/samba/smb.conf/target[1]/',
    changes => [
        "set workgroup ${ad_domain}",
        "set 'password\ server' ${ad_server}",
        "set realm ${realm}",
        'set security ads',
        "set 'idmap\ uid' 16777216-33554431",
        "set 'idmap\ gid' 16777216-33554431",
        "set 'template\ shell' /bin/bash",
        "set 'winbind\ use\ default\ domain' false",
        "set 'winbind\ offline\ logon' true",
        "set 'load\ printers' no",
        ],
    notify  => Service['winbind'],
}
## Configure Winbind
exec { 'Configure_Winbind':
        path => ['/usr/bin', '/usr/sbin', '/bin'],
  command    => "authconfig --enablewinbind --enablewinbindauth --smbsecurity ads  --enablewinbindoffline --smbservers=${ad_server} --smbworkgroup=${ad_domain} --smbrealm ${realm} --winbindtemplateshell=/bin/bash --enablemkhomedir --passalgo=sha512 --update",
        #unless  => "grep -c $ad_server /etc/krb5.conf",
  #notify  => File[$systemauth],
}
#exec { "EnableCreateHomeDir_Winbind":
#        path    => ["/usr/bin", "/usr/sbin", "/bin"],
#        command => "authconfig --enablemkhomedir --update",
#        #unless  => "grep -c adc1 /etc/krb5.conf",
#        #notify  => File[$systemauth],
#}

## Join AIS_SERVICES (on error delete /var/lib/samba/*.tdb)
exec { "Join_'${ad_domain}'_domain":
        path      => ['/usr/bin', '/usr/sbin', '/bin'],
        logoutput => false,
  command         => "net ads join -U ${winbind_user}%${winbind_password} createcomputer=\"Linux Servers\" osName=${operatingsystem}",
   #require => Augeas["smb.conf"],	
  unless          => "net ads testjoin 2>&1 |grep -c 'Join is OK'",
  notify          => Service['winbind'],
}
# Enable sudoers.d
file { 'Enable sudoers.d':
        path => '/etc/sudoers.d',
  ensure     => directory,
  owner      => 'root',
  group      => 'root',
  mode       => '0750',
        }
file_line { 'Enable sudoers.d':
        path => '/etc/sudoers',
        line => '#includedir /etc/sudoers.d',
        }
## Winbind service
service { 'winbind':
  ensure => 'running',
  enable => true,
}

#include resolv_conf
#
#        domainname  => "$domain",
#        searchpath  => 'it.company.com dpns.ais.company.com dev.ais.company.com ais.company.com',
#        nameservers => ['192.168.0.1', '192.168.1.1', '192.168.2.1'],
#        options     => ['timeout:2', 'attempts:3'],
#    }

## Development Environement
if $foreman_env == 'development' {

file { '/etc/sudoers.d/AIS_SERVICES_domain_users':
      replace => 'no', # this is the important property
      ensure  => 'present',
      content => "## Sudoers file managed by Puppet\n",
      mode    => '0440',
  }
file { '/etc/sudoers.d/AISDEV_domain_users':
        replace => 'no', # this is the important property
        ensure  => 'present',
        content => "## Sudoers file managed by Puppet\n",
        mode    => '0440',
        }

file_line { 'sudo_AIS_SERVICES_domain_users':
        path => '/etc/sudoers.d/AIS_SERVICES_domain_users',
        line => '%AIS_SERVICES\\domain\ users         ALL=(ALL)       ALL',
  require    => File['/etc/sudoers.d/AIS_SERVICES_domain_users'],
  notify     => Service['winbind'],
  }
file_line { 'sudo_AISDEV_domain_users':
        path => '/etc/sudoers.d/AISDEV_domain_users',
        line => '%AISDEV\\domain\ users         ALL=(ALL)       ALL',
  require    => File['/etc/sudoers.d/AISDEV_domain_users'],
  }
}
## Testing Environement
if $foreman_env == 'testing' {

file { '/etc/sudoers.d/AIS_SERVICES_domain_users':
        replace => 'no', # this is the important property
        ensure  => 'present',
        content => "## Sudoers file managed by Puppet\n",
        mode    => '0440',
  }

file_line { 'sudo_AIS_SERVICES_domain_users':
        path    => '/etc/sudoers.d/AIS_SERVICES_domain_users',
        line    => '%AIS_SERVICES\\domain\ users         ALL=(ALL)       ALL',
        require => File['/etc/sudoers.d/AIS_SERVICES_domain_users'],
  }
}
file { '/etc/krb5.conf':
        replace => 'yes', # this is the important property
        ensure  => 'present',
        mode    => '0655',
  source        => 'puppet:///modules/ad-member/krb5-ais_services.conf'
        }
## Production Environment
if $foreman_env == 'qa' {

file { $systemauth:
        source  => "puppet:///modules/ad-member/${systemauth}",
        owner   => 'root',
        group   => 'root',
        mode    => '0755',
        path    => "/etc/pam.d/${systemauth}",
        require => Exec['check_require_membership_of'],
        notify  => Service['winbind'],
        #subscribe => "/etc/pam.d/$systemauth",
        }

file { '/etc/sudoers.d/AIS_SERVICES_domain_admins':
        replace => 'no', # this is the important property
        ensure  => 'present',
        content => "## Sudoers file managed by Puppet\n",
        mode    => '0440',
        notify  => Service['winbind'],
        }
file_line { 'sudo_domain_users':
        path    => '/etc/sudoers.d/AIS_SERVICES_domain_admins',
        line    => '%AIS_SERVICES\\domain\ admins   ALL=(ALL)       ALL',
        require => File['/etc/sudoers.d/AIS_SERVICES_domain_admins'],
        }
exec { 'check_require_membership_of':
        command => '/bin/true',
        unless  => "/bin/grep -c require_membership_of /etc/pam.d/${systemauth}",
  }
}

if $foreman_env == 'production' {

file { $systemauth:
        source  => "puppet:///modules/ad-member/${systemauth}",
        owner   => 'root',
        group   => 'root',
        mode    => '0755',
        path    => "/etc/pam.d/${systemauth}",
        require => Exec['check_require_membership_of'],
  notify        => Service['winbind'],
  }

file { '/etc/sudoers.d/AIS_SERVICES_domain_admins':
        replace => 'no', # this is the important property
        ensure  => 'present',
        content => "## Sudoers file managed by Puppet\n",
        mode    => '0440',
  notify        => Service['winbind'],
        }
file_line { 'sudo_domain_users':
        path    => '/etc/sudoers.d/AIS_SERVICES_domain_admins',
        line    => '%AIS_SERVICES\\domain\ admins   ALL=(ALL)       ALL',
        require => File['/etc/sudoers.d/AIS_SERVICES_domain_admins'],
        }
exec { 'check_require_membership_of':
        command => '/bin/true',
        unless  => "/bin/grep -c require_membership_of /etc/pam.d/${systemauth}",
  }
  }
}

