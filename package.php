<?php

require_once 'PEAR/PackageFileManager2.php';
PEAR::setErrorHandling(PEAR_ERROR_DIE);

$api_version     = '0.0.0';
$api_state       = 'alpha';

$release_version = '0.0.0';
$release_state   = 'alpha';
$release_notes   = "No release notes.";

$description = <<<DESC
A JWT encoder/decoder.
DESC;

$package = new PEAR_PackageFileManager2();

$package->setOptions(
    array(
        'filelistgenerator'       => 'file',
        'simpleoutput'            => true,
        'baseinstalldir'          => '/',
        'packagedirectory'        => './',
        'dir_roles'               => array(
            'tests'               => 'test'
        ),
        'ignore'                  => array(
            'package.php',
            '*.tgz'
        )
    )
);

$package->setPackage('JWT');
$package->setSummary('A JWT encoder/decoder.');
$package->setDescription($description);
$package->setChannel('pear.php.net');
$package->setPackageType('php');
$package->setLicense(
    'MIT License',
    'http://creativecommons.org/licenses/MIT/'
);

$package->setNotes($release_notes);
$package->setReleaseVersion($release_version);
$package->setReleaseStability($release_state);
$package->setAPIVersion($api_version);
$package->setAPIStability($api_state);

$package->addMaintainer(
    'lead',
    'lcfrs',
    'Neuman Vong',
    'neuman+pear@twilio.com'
);

$package->addExtensionDep('required', 'json');
$package->addExtensionDep('required', 'hash');

$package->setPhpDep('5.1');

$package->setPearInstallerDep('1.7.0');
$package->generateContents();
$package->addRelease();

if (   isset($_GET['make'])
    || (isset($_SERVER['argv']) && @$_SERVER['argv'][1] == 'make')
) {
    $package->writePackageFile();
} else {
    $package->debugPackageFile();
}

?>
