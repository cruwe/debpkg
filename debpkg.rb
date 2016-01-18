require 'rubygems'
require 'json'

#-----------------------------------------------------------------------------
CMD    = $PROGRAM_NAME.split('/').last
subcmd = 'usage'
USAGE  = <<EOT
Usage: #{CMD} SUBCOMMAND [ARGUMENTS]

  where SUBCOMMAND is one of the following
  \t audit
  \t leaves
  \t usage
EOT
#-----------------------------------------------------------------------------

#-----------------------------------------------------------------------------
def verssplit(versstring,pkgdata,vulnspec)
  if versstring.nil?
    puts 'breakpoint'
  end

  if versstring.include?(':')
    versstring.gsub!(':', '.')
  else
    versstring = '0.' + versstring
  end

  unless versstring =~ /\+|~/
    versstring = versstring + "~0"
  end

  versstring = versstring.split(/\+|~|-/)

  vers = []
  versstring[0].split('.').each do |part|
    vers.push(part.to_i)
  end

  if vers.length == 3
    vers.push(0)
  end

  return vers
end

#verssplit(vers)
#-----------------------------------------------------------------------------

#-----------------------------------------------------------------------------
def array_geq(left, right)
  if left.length == 1
    return (left[0] >= right[0])
  else
    if (left[0] == right[0])
      res = array_geq(left.drop(1), right.drop(1))
      return res
    else
      res = (left[0] >= right[0])
      return res
    end
  end
end

#array_geq(left, right)
#-----------------------------------------------------------------------------

#-----------------------------------------------------------------------------
def version_geq(pkgdata, vulnspec, left, right)
  nleft  = verssplit(left,pkgdata,vulnspec)
  nright = verssplit(right,pkgdata,vulnspec)

  if nleft.length != nright.length
    #puts 'unclear version semantics for pkg ' + pkgname + ': ' +
    #         nleft.to_s + " ? " + nright.to_s + '. Aborting.'
    return 'invalid'
  else
    return array_geq(nleft, nright)
  end
end

#version_geq(left, right)
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

  pkgs = pkgs.sort_by { |k, v| v['compkey'] }

  return pkgs.to_h
end

# populate()
#-----------------------------------------------------------------------------

#-----------------------------------------------------------------------------
def audit
  pkgs = populate

  vulnstr = File.read('/home/cjr/tmp/debiansec')
  vulnstr.gsub!(/fixed_version/, 'fixedversion')
  vulns = JSON.parse(vulnstr)

  pkgs.each_pair do |pkgname, pkgdata|

    pkgsrc = pkgdata['Source']
    if vulns.has_key?(pkgsrc)

      vulns[pkgsrc].each do |vuln|
        vulnid    = vuln[0]
        vulnspec = vuln[1]

        if vulnspec['releases'].has_key?('jessie')
          probability = vulnspec['releases']['jessie']

          if probability['status'] == 'open'
            if vulnspec.has_key?('description')
              description= vulnspec['description']
            else
              description = 'No description available.'
            end
            puts pkgdata['compkey'] + ' ; ' + vulnid + ' ; ' +
                     description + "\n"
          elsif probability['status'] == 'undetermined'
            puts pkgdata['compkey'] + ' ; ' + vulnid + ' ; ' +
                     "undetermined\n"
          # else # then probability['status'] == "resolved"
          # -----------------------------------------------
          # this code will not work because of countless exceptions to the
          # versioning semantics as described in deb-version(5)
          # until I have an idea how to compare versions of different length,
          # this function cannot be completedq
          #   fixvstr = vulnspec['releases']['jessie']['fixedversion']
          #   curvstr = pkgdata['Version']
          #
          #   # if pkgname == 'xserver-common'
          #   #   puts 'breakpoint'
          #   # end
          #
          #   fixed = version_geq(pkgs[pkgname],vulnspec, curvstr, fixvstr)
          #   if fixed == false
          #     puts pkgdata['compkey'] + ' vulnerable, patch available, fix it!'
          #   end

          end
        end
      end
    end
  end

end

# audit()
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
end

# leaves()
#-----------------------------------------------------------------------------

unless (ARGV.empty? ||
    ARGV[0].start_with?('-'))
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

