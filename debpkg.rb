require 'rubygems'
require 'json'
require 'versionomy'


#-----------------------------------------------------------------------------
CMD    = $PROGRAM_NAME.split('/').last
subcmd = 'usage'
USAGE = <<EOT
Usage: #{CMD} SUBCOMMAND [ARGUMENTS]

  where SUBCOMMAND is one of the following
  \t audit
  \t leaves
  \t usage
EOT
#-----------------------------------------------------------------------------

#-----------------------------------------------------------------------------
def populate
  pkgs      = {}

  #dpkgstatf = File.open('./testdata/pkg', "r")
  dpkgstatf = File.open('/var/lib/dpkg/status', 'r')
  dpkgstatd = dpkgstatf.read
  dpkgstatf.close


  pkgname = ""
  pkgdata = {}

  dpkgstatd.each_line do |line|
    line.chomp!

    if line.start_with?(' ')
      #ignore long description
    elsif line =~ /^Package:/
      pkgname = line.split(': ')[1]
    elsif line.empty?
      unless pkgdata.empty?
        pkgs[pkgname] = pkgdata
        pkgdata       = {}
      end
    else
      pair             = line.split(': ')
      pkgdata[pair[0]] = pair[1]
    end

  end

  pkgs.each_pair do |pkgname, pkgdata|
    pkgdata['compkey'] = pkgdata['Section'] + '/' + pkgname

    if pkgdata.has_key?('Depends')

      dependencies = pkgdata['Depends'].split(',')
      dependencies.each do |dependency|
        deppkg = dependency.split(' ')

        if pkgs.has_key?(deppkg[0])
          pkgs[deppkg[0]]['isDependency'] = :true
        end
      end
    end
  end

  pkgs = pkgs.sort_by { |k,v| v['compkey'] }

  return pkgs.to_h
end # populate()
#-----------------------------------------------------------------------------

#-----------------------------------------------------------------------------
def audit
  pkgs = populate

  vulnstr = File.read('/home/cjr/tmp/debiansec')
  vulnstr.gsub!(/fixed_version/,'fixedversion')
  vulns = JSON.parse(vulnstr)

  pkgs.each_pair do |pkgname, pkgdata|

    pkgsrc = pkgdata['Source']
    if vulns.has_key?(pkgsrc)

      vulns[pkgsrc].each do |vuln|
        vulnid = vuln[0]
        vulndescr = vuln[1]

        if vulndescr['releases'].has_key?('jessie')
          probability = vulndescr['releases']['jessie']

          if probability['status'] == "open"
            if vulndescr.has_key?('description')
              description= vulndescr['description']
            else
              description = 'No description available.'
            end
            puts 'alerting for package ' + pkgdata['Section'] + '/' + pkgname + ' : ' +
                     'Vulnerability ' + vulnid + ' is described as follows: ' +
                     description + "\n\n"
          end
        end
      end
    end
  end

end # audit()
#-----------------------------------------------------------------------------

#-----------------------------------------------------------------------------
def leaves
  pkgs = populate
  pkgs.each_pair do |pkgname, pkgdata|
    unless pkgdata.has_key?('isDependency')
      puts pkgdata['Section'] + '/' + pkgname +
               ' (' + pkgdata['Priority'] + ')' + ': ' +
               pkgdata['Description']
    end
  end
end # leaves()
#-----------------------------------------------------------------------------

unless (ARGV.empty? || ARGV[0].start_with?('-'))
  subcmd = ARGV.shift
end


case subcmd
  when 'leaves'
    leaves
  when 'audit'
    audit
  else
    puts USAGE
end

