#!/usr/bin/env python3

# Copyright (c) 2022, Cisco Systems, Inc. and/or its affiliates.
# All rights reserved.
# See accompanying LICENSE file in apt2sbom distribution.

"""
Convert apt and pip information to SPDX JSON format.

Future: https://pkg.go.dev/pault.ag/go/debian/control

https://github.com/paultag/go-debian

https://www.chainguard.dev/unchained/what-your-scanner-doesnt-know-cant-hurt-you
"""

import os
import re
import sys
import json
from datetime import datetime
from socket import gethostname
from pprint import pprint

import requests
from apt.cache import Cache
from apt.debfile import DebPackage
# from debian.debfile import DebFile

# https://github.com/ms7m/debian-packages-parser/tree/master/debian_parser

import itertools


class PackagesParser(object):
    def __init__(self, raw_packages_file):

        self._extra_strings_added = 0

        data_raw = raw_packages_file.splitlines()

        if data_raw[0] != "":
            data_raw.insert(0, "")
            self._extra_strings_added += 1

        if data_raw[-1] != "":
            data_raw.append("")
            self._extra_strings_added += 1

        self._data_splitted = data_raw

        if self._extra_strings_added != 0:
            self._extra_strings_added -= 1

        self._parse_to_seperated_lists()

    def _splitted_lines(self):
        return self._data_splitted.count("") - self._extra_strings_added

    def _parse_to_seperated_lists(self):

        # TODO: PLEASE REWRITE THIS IS
        # IS EXTREMELY UGLY
        #
        # It's basically just splitting the .splitlines()
        # into indiv. list seperated by < "" >

        size_of_splitlines = len(self._data_splitted)

        get_new_line_indexes = [
            index + 1
            for index, index_value in enumerate(self._data_splitted)
            if index_value == ""
        ]

        incomplete_data = [
            self._data_splitted[index_to_start:index_to_end]
            for index_to_start, index_to_end in zip(
                [0] + get_new_line_indexes,
                get_new_line_indexes
                + (
                    [size_of_splitlines]
                    if get_new_line_indexes[-1] != size_of_splitlines
                    else []
                ),
            )
        ]

        for sub_list in incomplete_data:
            for element_index, element in enumerate(sub_list):
                if element == "":
                    sub_list.pop(element_index)

        for sub_list_element, sub_list in enumerate(incomplete_data):
            if sub_list == []:
                incomplete_data.pop(sub_list_element)

        self._data = incomplete_data
        return self._data

    def _parse_string(self, string):

        if string == "":
            return False

        selected_string_split = string.split()
        selected_string_top = selected_string_split[0]
        selected_string_top_chars = [x for x in selected_string_top]

        if selected_string_top_chars.count(":") == 1:
            if "http" in selected_string_top:
                return False
            return True

        return False

    def _parse_to_dict(self):
        end_result = []

        for element_list in self._data:

            selected_child = []
            for selected_elements_index, selected_element in enumerate(element_list):

                selected_element_check = self._parse_string(selected_element)
                if selected_element_check == True:

                    selected_element_splitted = selected_element.split()
                    selected_element_key = selected_element_splitted[0]
                    selected_element_value = " ".join(selected_element_splitted[1:])

                    # check if the next values should be appended.

                    for inter_step in itertools.count(selected_elements_index + 1):
                        try:
                            selected_element_future = element_list[inter_step]
                            future_index_to_check = self._parse_string(
                                selected_element_future
                            )
                            if future_index_to_check == True:
                                break
                            else:
                                selected_element_value += " " + element_list[inter_step]
                        except IndexError:
                            break

                    selected_child.append(
                        {
                            "tag": selected_element_key.strip(":"),
                            "value": selected_element_value,
                        }
                    )
                else:
                    continue

            end_result.append(selected_child)
        return end_result

    def parse(self):
        if self._data:
            return self._parse_to_dict()

        self._parse_to_seperated_lists()
        return self._parse_to_dict()


def tojson(pattern = None, dopip=False):
    """
    Convert APT information to SPDX JSON.
    """

    sbom = { }
    cinfo = { }
    pkgs = [ ]
    pkgids = [ ]
    deps = {}
    rels = []
    sbom = {
        "spdxVersion" : "SPDX-2.2",
        "SPDXID" : "SPDXRef-DOCUMENT",
        "dataLicense" : "CC0-1.0",
        "name" : "apt2sbom-" + gethostname(),
        "documentNamespace" : "https://" + gethostname() + "/.well-known/transparency/sbom"
    }
    cinfo["creators"] =  [ "Tool: apt2sbom-ubuntu-1.0" ]
    cinfo["created"] = str(re.sub(r'..*$','',datetime.now().isoformat())) + 'Z'
    sbom['creationInfo']= cinfo

    files = []
    for root, dirnames, filenames in os.walk("packages"):
        for filename in filenames:
            if filename.endswith(".deb"):
                files.append(os.path.join(root, filename))
    packages_files = []
    for root, dirnames, filenames in os.walk("packages"):
        for filename in filenames:
            if filename.endswith("Packages.gz"):
                packages_files.append(os.path.join(root, filename))

    # Parse the various release files - combine them into single dictionary
    packages_metadata = []
    if not os.path.exists("packages/metadata.json"):
        import gzip
        for file in packages_files:
            with gzip.open(file, 'rb') as f:
                file_content = f.read()
            parser = PackagesParser(file_content.decode("utf-8"))
            data = parser.parse()
            packages_metadata = packages_metadata + data
        with open("packages/metadata.json", "w") as f:
            print("[!] Saving packages/metadata.json file...")
            f.write(json.dumps(packages_metadata))
    else:
        packages_metadata = json.loads(open("packages/metadata.json").read())

    for file in files:
        # Extract "depends" information from the .deb file
        deb = DebPackage(file)
        depends = deb.depends
        found = False
        info = None
        basename = os.path.basename(file)
        for package in packages_metadata:
            for tagpair in package:
                tag_name = tagpair["tag"]
                tag_value = tagpair["value"]
                if basename in tag_value and tag_name == "Filename":
                    info = package
                    found = True
                    break
        pkg_name = None
        version = None
        maintainer = None
        homepage = None
        md5sum = None
        sha256 = None
        sha1 = None
        filename = None
        source = None
        for tagpair in info:
            tag_name = tagpair["tag"]
            tag_value = tagpair["value"]
            if tag_name == "Package":
                pkg_name = tag_value
            if tag_name == "Version":
                version = tag_value
            if tag_name == "Maintainer":
                maintainer = tag_value
            if tag_name == "Homepage":
                homepage = tag_value
            if tag_name == "MD5sum":
                md5sum = tag_value
            if tag_name == "SHA256":
                sha256 = tag_value
            if tag_name == "SHA1":
                sha1 = tag_value
            if tag_name == "Filename":
                filename = tag_value
            if tag_name == "Source":
                source = tag_value
        pack = {}
        pack["name"] = pkg_name
        pack["SPDXID"] = "SPDXRef-apt2sbom." + pkg_name
        pkgids.append(pack["SPDXID"])
        pack["versionInfo"] = version
        pack["filesAnalyzed"] = False
        pack["supplier"] = "Organization: " + maintainer
        pack["homepage"]= homepage
        # "sourceInfo": "built package from: tar 1.34+dfsg-1build3"
        pack["sourceInfo"]= "built package from: %s %s" % (source or pkg_name, version)
        pack["externalRefs"] = [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/%s@%s?arch=amd64&distro=ubuntu" % (pkg_name, version)
        }]

        hashes= []
        try:
            hashes.append({ "algorithm" : 'SHA256',
                       'checksumValue' : sha256 })
        except SystemError:
            pass

        try:
            hashes.append({ "algorithm" : 'SHA1',
                       'checksumValue' : sha1 })
        except SystemError:
            pass

        try:
            hashes.append({ "algorithm" : 'MD5',
                       'checksumValue' : md5sum })
        except SystemError:
            pass

        if hashes:
            pack['checksums'] = hashes

        if filename:
            from urllib.parse import urljoin
            pack["downloadLocation"] = urljoin("http://archive.ubuntu.com/ubuntu/", filename)
        else:
            pack["downloadLocation"] = "http://spdx.org/rdf/terms#noassertion"
        if depends:
            deps[pkg_name] = []
            for dep in depends:
                tname = dep[0][0]
                deps[pkg_name].append(tname)
            if deps[pkg_name] == []:
                deps.pop(pkg_name)
        pack["licenseConcluded"] = "NOASSERTION"
        pack["licenseDeclared"] = "NOASSERTION"
        pack["copyrightText"] = "NOASSERTION"
        pkgs.append(pack)

    # Hack
    static_pkgs = [
    {
      "name": "ubuntu:CORRUPT",
      "SPDXID": "SPDXRef-ContainerImage-XYZ"
    },
    {
      "name": "ubuntu",
      "SPDXID": "SPDXRef-OperatingSystem-XYZ",
      "versionInfo": "23.04",  # make me dynamic!
      "downloadLocation": "NONE",
      "copyrightText": "",
      "primaryPackagePurpose": "OPERATING-SYSTEM"
    }]

    sbom['packages'] = static_pkgs + pkgs
    sbom['documentDescribes'] = pkgids
    for pname in deps:
        for dep in deps[pname]:
            rec_info = {
                  'spdxElementId' : "SPDXRef-apt2sbom." + pname,
                  'relationshipType' : 'DEPENDS_ON',
                  'relatedSpdxElement' : "SPDXRef-apt2sbom." + dep
            }
            rels.append(rec_info)

    # Hack
    static_rels = [{
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-ContainerImage-XYZ",
      "relationshipType": "DESCRIBES"
    },
    {
      "spdxElementId": "SPDXRef-ContainerImage-XYZ",
      "relatedSpdxElement": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS"
    }]

    # Package->OS relationships
    dynamic_rels = []
    for pname in deps:
        rec_info = {
                'spdxElementId' : "SPDXRef-OperatingSystem-XYZ",
                'relationshipType' : "CONTAINS",
                'relatedSpdxElement' : "SPDXRef-apt2sbom." + pname
        }
        dynamic_rels.append(rec_info)

    sbom['relationships'] = rels + static_rels + dynamic_rels

    return json.dumps(sbom)


def download_file(url, local_filename):
    # NOTE the stream=True parameter below
    print("[+] Grabbing %s" % url)
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    return local_filename


def grab_packages_and_metadata(package_list="out/packages.txt"):
    packages = []
    with open(package_list) as f:
        for line in f.readlines():
            packages.append(line.strip())

    for package in packages:
        base_dir = "packages"
        if package.endswith(".deb"):
            base_path = os.path.join(base_dir, package.split("/")[-1])
            if not os.path.exists(base_path):
                download_file(package, base_path)
        else:
            base_path = package.replace("http://archive.ubuntu.com/ubuntu/dists/", "")
            base_dir = os.path.dirname(base_path)
            if base_dir:
                try:
                    os.makedirs(os.path.join("packages", base_dir))
                except:
                    pass
            if not os.path.exists(os.path.join("packages", base_path)):
                download_file(package, os.path.join("packages", base_path))

grab_packages_and_metadata()

print(tojson())
