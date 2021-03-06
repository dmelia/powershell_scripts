<######################################################################
Outil d'administrateur windows serveur 2019

V1.0 February 2021

Written By Guilhem SCHLOSSER

All Code provided as is and used at your own risk.
######################################################################>

####################################################################### FONCTIONS ANNEXE ######################################################################


####################################
# Fonction explorateur de fichiers #
####################################

function Explorer {
Add-Type -AssemblyName System.Windows.Forms
    # Open Browser Explorer
        $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ InitialDirectory = [Environment]::GetFolderPath('Desktop') }
        $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
            InitialDirectory = [Environment]::GetFolderPath('Desktop') 
            Filter = 'Documents (*.csv)|*.csv'
        }
}

###################################################################### FONCTIONS ######################################################################

######################################
# Installation d'un Active Directory #
######################################


function Install_AD {
    # Remplace le nom g�n�rique du serveur par le nom choisi et red�marrage du serveur
    workflow Resume_Workflow
    {
        Rename-Computer -NewName $SRV_name -Force -Passthru
        Restart-Computer -Wait
    }

    [string] $Load_Configuration = Read-Host "Charger la configuration ? Y/N "
    [string] $SRV_name
    [string] $IPv4
    [string] $Mask
    [string] $Gateway
    [string] $IP_dns
    [string] $name_domain

    if ($Load_Configuration -eq "y" -or $Load_Configuration -eq "Y") {
        $Configuration = Get-Content -Path ".\AD_CONF.json" | ConvertFrom-Json
        $SRV_name = $Configuration.SRV_name
        $IPv4 = $Configuration.IPv4
        $Mask = $Configuration.Mask
        $Gateway = $Configuration.Gateway
        $IP_dns = $Configuration.IP_dns
        $name_domain = $Configuration.name_domain
        $ipif_index = $Configuration.ipif_index

        Write-Host $SRV_name
    } else {
        $SRV_name = Read-Host "Renseigner le nom du server "
        $IPv4 = Read-Host "Renseigner l'adresse IPv4 du serveur "
        $Mask = Read-Host "Renseigner le masque de sous r�seau exemple seulement 24 for /24 "
        $Gateway = Read-Host "Renseigner la passerelle "
        $IP_dns = Read-Host "Renseigner le DNS (normalement si c'est un AD c'est lui m�me) "
        $name_domain = Read-Host "Renseigner le nom de domaine "

        Write-Host "Interfaces infos :"
        Get-NetAdapter

        [string] $ipif_index = Read-Host "Renseigner l'index de l'interface "
        $Carte = Read-Host "Renseigner le nom de l'interface ou vous souhaitez d�sactiver IPv6 "
    }
    
    Try {
        Remove-NetIPAddress -InterfaceIndex $ipif_index
        Disable-NetAdapterBinding -Name "$Carte"  -ComponentID ms_tcpip6
    }
    Catch {
        Write-host "La carte " $Carte " n'est pas pr�sente ou est d�j� d�sactiv�e"
    }
    
    


    Write-Host "`n===== Installation d'un active directory =====`n" -BackgroundColor DarkGray

    # T�ches effectu�es apr�s le red�marrage du server:
    # - Adressage IP / Nom de la nouvelle For�t / installation du DNS et param�trage de son IP.


    # Permet d'attribuer l'IP / Masque / Gateway au server
    Try {
        New-NetIPAddress -InterfaceIndex $ipif_index -IPAddress $IPv4 -PrefixLength $Mask -DefaultGateway $Gateway
    }
    Catch {
        Write-host "L'adresse IP est d�j� attribu�e � l'interface"
    }

    # Permet d'attribuer un DNS au server
    Set-DnsClientServerAddress -InterfaceIndex $ipif_index -ServerAddresses ("$IP_dns")

    # Installe les service necessaire � la cr�ation d'un Active directory
    Install-WindowsFeature -Name "AD-Domain-Services" -IncludeManagementTools

    # Param�trage des diff�rentes informations de l'Active directory
    # https://docs.microsoft.com/en-us/powershell/module/addsdeployment/install-addsforest?view=win10-ps

    Install-ADDSForest `
            -DomainName $name_domain `
            -CreateDnsDelegation:$false `
            -DatabasePath "C:\Windows\NTDS" `
            -DomainMode "7" `
            -ForestMode "7" `
            -InstallDns:$true `
            -LogPath "C:\Windows\NTDS" `
            -NoRebootOnCompletion:$false `
            -SysvolPath "C:\Windows\SYSVOL" `
            -Force:$true

    # Check du DNS dans sa config initiale
    Get-DnsServerZone

    # Ajout de la zone de recherche invers�
    Add-DnsServerPrimaryZone -Network ("127.0.0.1") -ReplicationScope "Domain"
    # Check des modifications du Dns
    Get-DnsServerZone

    # Check des erreurs
    $error

    Write-Host "`n======= Fin du script ========`n" -BackgroundColor Green
    Write-Host "`n======= Veuillez r�demarrer le serveur ========`n" -BackgroundColor Red
    break

}

######################################################################

#####################
# Installation DHCP #
#####################

function Install_DHCP {
    Write-Host " Installation du Role DHCP et pr�s param�trage "
    [string]$Address = Read-Host -Prompt "Renseigner l'adresse IP du serveur : "
    Install-WindowsFeature -Name DHCP -IncludeManagementTools
    Add-DhcpServerInDC -DnsName 127.0.0.1 -IPAddress $Address
}

############################
# Check et Cr�ation des OU #
############################


function Create_OU_manual
{
    # Efface tout ce qu'il y a dans la console. Ainsi que les erreurs des pr�c�dante commandes ou scripts.
    Clear-Host

    # Module
    Import-Module ActiveDirectory

    Write-Host "`n===== Cr�ation de d''unit� organisationnelle =====`n" -BackgroundColor DarkGray
    Write-Host ""
    Write-Host ""
    $DomainName = (Get-WmiObject Win32_ComputerSystem).Domain
    Write-Host "Votre domaine s'appelle $DomainName"
    Write-Host ""
    Write-Host ""
    Write-Host ""

    # Question
    $Path_DC = Read-Host -Prompt 'DC=exemple,DC=com'
    $createOUName = Read-Host -Prompt 'Nommer la nouvelle unit� organisationnelle (OU) :'


    Try {
        Get-ADOrganizationalUnit -Identity ('OU=' + $createOUName + ',' + $Path_DC)
        $isCreated = $true
        Write-host "L''unit� organisationnelle " $createOUName " existe d�j�" -ForegroundColor Red
    }
    Catch {
        $isCreated = $false
        Write-host  "L''unit� organisationnelle $createOUName n''existe pas et va donc �tre cr��" -ForegroundColor Yellow
    }
    If ($isCreated -eq $false) {
        New-ADOrganizationalUnit -Name $createOUName -Path $Path_DC -ProtectedFromAccidentalDeletion $False #Protection suppressive OU disable
        Write-host  "Cr�ation de l''unit� organisationnelle $createOUName termin�" -ForegroundColor Green
    }

    # Choix � l'utilisateur de continuer ou non l'execution de la fonction afin de cr�er des sous OU
    Write-Host "Souhaitez-vous cr�er des sous unit�s organisationnelle ?"-ForegroundColor Yellow
    $annuler = ![bool]$reponse
    $reponse = read-host "Presser la touche [a] pour annuler, ou n'importe qu'elle touche pour continuer." -ForegroundColor Cyan
    $annuler = $response -eq "a"

    # Ajout pour cr�ation de sous OU

    $createSubOUName = Read-Host 'Entrer le ou les noms des nouvelles unit� organisationnelle a cr�er. `\ntel que OU=Utilisateurs,OU=Comptabilite,OU=Chef,'
    $ouName = Read-Host 'Entre le nom de l''unit� organisationnelle racine dans laquelles ' $createSubOUName 'sera ou seront plac�s ?'
    $FullPath = ('OU=' + $ouName + ',' + $Path_DC)

    Write-Host $FullPath

    # Je renseigne le chemin complet de mes OU, je dis ou je veux que celle-ci soit plac� (dans qu'elle OU), ensuite je fait 'OU custom' -Path (OU de base + FQDN) 

    If (Get-ADOrganizationalUnit -Filter { Name -like $ouName }) {
        $isCreated = $true
        Write-Host "L''existance de l''unit� organisationnelle $ouName a �t� v�rifi� et valid� et nous pouvons donc continuer" -ForegroundColor Green
    } Try {
        Get-ADOrganizationalUnit -Identity ($createSubOUName + 'OU=' + $ouName + ',' + $Path_DC)
        $isCreated = $true
        Write-Host "La ou les unit�(s) organisationnelle(s) $createSubOUName existe(s) d�j�" -ForegroundColor Red
    }  Catch {
        $isCreated = $false
        Write-Host "La ou les unit�(s) organisationnelle(s) $createSubOUName n'existe(nt) pas est va/vont donc �tre cr��(es)" -ForegroundColor Yellow
    }
    If ($isCreated -eq $false) {
        New-ADOrganizationalUnit -Name $createSubOUName -Path $FullPath -ProtectedFromAccidentalDeletion $false #Protection suppressive OU disable
        Write-Host "La ou les unit�(s) organisationnelle(s) $createSubOUName a (ont) �t� cr��(es)" -ForegroundColor Green
    }

    Write-Host "`n======= Fin du script ========`n" -BackgroundColor Green
    # Check des erreurs
    $error
    break
}

######################################################################

########################################################
# creation des comptes utilisateurs et cr�ation des OU #
########################################################

function Import_user_and_groups_from_csv {
    # Efface tout ce qu'il y a dans la console. Ainsi que les erreurs des pr�c�dante commandes ou scripts.
    Clear-Host

    # Module
    Import-Module ActiveDirectory

    Write-Host "`n===== Script de cr�ation Utilisateurs, OU & Groupes =====`n" -BackgroundColor DarkGray

    # En cas d'erreur du script on continue
    $ErrorActionPreference = "Continue"

    # Import du Module AD
    Import-Module activedirectory


    # Variables
    $Domain = (Get-ADDomain).DNSRoot


    # Import du fichier Csv contenant la liste des utilisateurs et groupes (appel du chemin par la function Explorer qui elle m�me renvoit la $File)  traiter et pour chaque objet
    $File = Import-CSV $FileBrowser  -Delimiter ";" | Format-Table | ForEach-Object {


        # Variables fixes

        $lastname = $_.Surname  # Nom
        $firstname = $_.GivenName # Prenom
        $SamAccountName = $_.SamAccountName # Login
        $DisplayName = $_.GivenName + " " + $_.Surname # Nom Affich� � l'�cran de l'ordinateur
        $Department = $_.Department # Services auquel l'utilisateur appartient
        $RawPassword = $_.Password # Mot de passe
        $Group = $_.Group #Groupe auquel l'utilisateur appartient
        $Description = $_.Description # R�le ou Job de l'utilisateur
        $login = $firstname.Substring(0, 1) + "." + $lastname.ToUpper()
        $OU = $_.OU #OU pour chaque utilisateurs

        # Variable Compl�mentaires
        $UPN = "$SamAccountName@$Domain" # permettra en cas de besoin par la suite de cr�er automatiquement le champ mail de l'utilisateur

        $Password = ConvertTo-SecureString -AsPlainText $RawPassword -Force # Gestion des mots de passe en clair

        ############################################
        # creation des OU  si elles n'existent pas #
        ############################################

        $split = $OU.Split(',') #On d�coupe le chemin complet de la OU (dans le CSV) avec le s�parateur dans la ligne qui est une virgule
        $chemin = $split[$split.length - 2] + ',' + $split[$split.length - 1] #Cela cr�er un tableau


        for ($i = $split.length - 3; $i -ge 0; $i --) {
            $Path = $chemin
            $Name = $Split[$i].Split('=')[1]
            $chemin = $split[$i] + ',' + $chemin
            write-host $chemin

            # on essaye de recuper l'ou
            Try {
                Get-ADOrganizationalUnit -Identity $chemin
                $isCreated = $true
                Write-Host 'La $chemin existe'
            }


            # si elle existe on ne fait rien
            Catch {
                write-host $Path $OU
                New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $true
                Write-Host "Cr�ation de l''unit� organisationnelle $chemin effectu� avec succ�s"
            }
        }

        New-ADUser -GivenName $firstname -Surname $lastname -SamAccountName $login -Name $SamAccountName -DisplayName $DisplayName -UserPrincipalName $UPN -Path $OU -AccountPassword $Password -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false


        # V�rification de la cr�ation de l'utilisateur
        if ($?) {
            Write-Host "Utilisateur $DisplayName cr�� avec succs !" -BackgroundColor DarkGreen
        } else {
            Write-Host "Erreur lors de la cr�ation de l'utilisateur $DisplayName !" -BackgroundColor DarkRed
        }

    }


    Write-Host "`n======= Fin du script ========`n" -BackgroundColor Green


    $error
    break
}


######################################################################

#################################
# Cr�ation de groupe (manuelle) #
#################################

function Create_group {
    # Efface tout ce qu'il y a dans la console. Ainsi que les erreurs des pr�c�dante commandes ou scripts.
    Clear-Host

    # Module
    Import-Module ActiveDirectory

    Write-Host "`n===== Cr�ation de groupe (manuel) =====`n" -BackgroundColor DarkGray


    # Variable
    $Name_Group = Read-Host -Prompt 'Renseigner le nom du nouveau groupe : '
    $Group_Scope = Read-Host -Prompt 'D�finisser le type (du groupe) ==> Domain local / Global / Universal (par defaut un groupe est Global) : '
    $Display_Name = Read-Host -Prompt 'Renseigner le nom qui sera affich� : '
    $Description = Read-Host -Prompt 'Renseigner une description du groupe : ' $Name_Group

    $ou = Read-Host 'Entrer le chemin de l''unit� organisationnelle ou sera plac� le nouveau groupe avec la syntaxe suivante ===> ou=Utilisateur : '  # syntaxe ou=Utilisateur / ou=chef
    $DC = Read-Host 'Entrer le nom de domaine avec la syntaxe suivante ===> DC=exemple,DC=com : ' # syntaxe dc=eris,dc=local pour eris.local 



    ###############################
    # Check Existing OU or Create #
    ###############################


    # Check if the group exist
    Try {
        Get-ADGROUP ($Name_Group + ',' + $OU + ',' + $DC)
        $isCreated = $true
    } Catch {
        Write-host $Name_Group ' N''existe pas et va donc �tre cr��' -BackgroundColor Green
        $isCreated = $false
    }
    If ($isCreated -eq $true) {
        Write-Host 'Le groupe '$Name_Group ' exite d�j�' -BackgroundColor Red
    } else {
        # -GroupCategory Distribution est pour les serveurs de mail
        New-ADGroup -Name $Name_Group -SamAccountName $Name_Group -GroupCategory Security -GroupScope $Group_Scope -DisplayName $Display_Name -Path ($ou + ',' + $DC) -Description $Description
        Write-Host 'Le nouveau groupe' $Name_Group 'a �t� cr��' -BackgroundColor Green
    }

    # Pour un compte de messagerie
    # New-ADGroup -Name -SamAccountName -GroupCategory Security -GroupScope Global -DisplayName -Path -Description
    Write-Host "`n======= Fin du script ========`n" -BackgroundColor Green

}

###################################################################### VARIABLE ######################################################################

$Title = 'Administration de serveur Windows 2019'

#...MENU
while ($true) {
    $i++
    Write-Host " "
    Write-Host " "
    Write-Host " "
    Write-Host "************************************************************************"
    Write-Host "================ $Title ================" -ForegroundColor Green
    Write-Host "************************************************************************"
    Write-Host " "
    Write-Host " "
    Write-Host " "
    Write-Host " "
    Write-Host "                    !!! use at your own risk !!!" -ForegroundColor Red
    Write-Host " "
    Write-Host " "
    Write-Host " "
    Write-Host " "
    Write-Host "             Le fichier CSV doit contenir (sans quoi rien ne fonctionnera pas)"
    Write-Host "Surname | GivenName	|	SamAccountName	|	Department	|	OU	|	Password	|	Group	|	Description"
    Write-Host " "
    Write-Host " "
    Write-Host " "
    Write-Host "  Le nom d''utilisateur du compte utilisateur est contenue dans la colonne SamAccountName"
    Write-Host "                                    exemple a.DUPOND"
    Write-Host " "
    Write-Host " "
    Write-Host " "
    Write-Host " Le nom d''utilisateur du compte utilisateur est contenue dans la colonne Surname"
    Write-Host " "
    Write-Host " "
    Write-Host " "
    Write-Host " Le pr�nom de l''utilisateur du compte utilisateur est contenue dans la colonne GivenName"
    Write-Host " "
    Write-Host " "
    Write-Host " "
    Write-Host "Presser '1' Pour installer un Active Directory." -ForegroundColor Cyan
    Write-Host " "
    Write-Host "Presser '2' Pour cr�er de(s) Unit�(s) Organisationnelle(s) et arborescence [EN MANUEL]" -ForegroundColor Cyan
    Write-Host " "
    Write-Host "Presser '3' Pour importer un (des) utilisateur(s) et un (des) groupe(s) � partir d''un fichier CSV" -ForegroundColor Cyan
    Write-Host " "
    Write-Host "Presser '4' Pour cr�er un groupe [EN MANUEL]" -ForegroundColor Cyan
    Write-Host " "
    Write-Host "Presser '5' Pour installer un serveur DHCP [EN MANUEL]" -ForegroundColor Cyan
    Write-Host " "
    Write-Host "Presser '6' to quit." -ForegroundColor Cyan
    Write-Host " "
    Write-Host " "

    $Menu = Read-Host -Prompt 'Selectionner une action '


    ###################################################################### SWITCH ######################################################################


    switch ($Menu) {
        '1' {
            Install_AD
        }
        '2' {
            Create_OU_manual
        }
        '3' {
            Import_user_and_groups_from_csv
        }
        '4' {
            Create_group
        }
        '5' {
            Install_DHCP
        }
        '6' {
            return
        }
        default {
            Write-Host "Veuillez rentrer une option valide."
        }
    }
}
