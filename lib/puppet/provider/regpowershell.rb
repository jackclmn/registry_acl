# Lifted from https://raw.githubusercontent.com/voxpupuli/puppet-iis/master/lib/puppet/provider/iispowershell.rb
require 'tempfile'

class Puppet::Provider::Regpowershell < Puppet::Provider
  initvars

  commands :powershell =>
    if File.exist?("#{ENV['SYSTEMROOT']}\\sysnative\\WindowsPowershell\\v1.0\\powershell.exe")
      "#{ENV['SYSTEMROOT']}\\sysnative\\WindowsPowershell\\v1.0\\powershell.exe"
    elsif File.exist?("#{ENV['SYSTEMROOT']}\\system32\\WindowsPowershell\\v1.0\\powershell.exe")
      "#{ENV['SYSTEMROOT']}\\system32\\WindowsPowershell\\v1.0\\powershell.exe"
    else
      'powershell.exe'
    end

  def self.run(command,precommand=nil)

    command.prepend(precommand) if !precommand.nil?
    utilpath = File.expand_path('../../../puppet_x/util', __FILE__)
    utilpath = File.join(utilpath, 'Set-LHSTokenPrivilege.ps1').gsub(File::SEPARATOR, File::ALT_SEPARATOR)
    newcommand = "\n. #{utilpath}\n"
    newcommand << "Set-LHSTokenPrivilege -Privilege SeRestorePrivilege -ErrorAction stop | out-null\n"
    newcommand << "Set-LHSTokenPrivilege -Privilege SeBackupPrivilege -ErrorAction stop | out-null \n"
    newcommand << "Set-LHSTokenPrivilege -Privilege SeTakeOwnershipPrivilege -ErrorAction stop | out-null\n"
    newcommand << command
    newcommand << "\n"
    newcommand << "Set-LHSTokenPrivilege -Privilege SeRestorePrivilege -disable | out-null\n"
    newcommand << "Set-LHSTokenPrivilege -Privilege SeBackupPrivilege -disable | out-null\n"
    newcommand << "Set-LHSTokenPrivilege -Privilege SeTakeOwnershipPrivilege -disable | out-null\n"


    time = Time.new
    output = powershell(newcommand)
    Puppet.debug "Reg_acl: Powershell Command result - #{output}"
    endtime = Time.new
    Puppet.debug "Reg_acl: Powershell command execution time: #{((endtime-time)*1000.0).round(2)} ms"

    return output
  end
end
