import os, json, collections


def grabGroupList(attack_path):
    ''' Reads the Enterprise json stig and returns a list of all groups in the stig'''
    attack_json = ""
    with open(attack_path, 'rb') as f:
        attack_json = f.read()
        attack_obj = json.loads(attack_json)

        group_list = []
        #Search through the ATT&CK objects to create a list of the group objects
        for entry in attack_obj["objects"]:
                if  isinstance(entry.get("external_references"), collections.Iterable)  :
                    ext_ref = entry.get("external_references")
                    revoked = entry.get("revoked")
                    foundIndex = findIndexGid(ext_ref)
                    if foundIndex != -1:
                        if  ext_ref[foundIndex].get("external_id") is not None and "G" in ext_ref[foundIndex].get("external_id") and (revoked is None or not revoked):
                            #print(ext_ref[0].get("external_id"))
                            group_list.append(entry)
    return group_list

def findIndexGid(ext_ref):
    count = 0
    flag = True
    while count < len(ext_ref) and flag:
        if ext_ref[count].get("external_id") is not None:
            flag = False
        else:
            count = count + 1
    if flag:
        return -1
    return count

def grabTechniqueList(attack_path):
    ''' Reads the Enterprise json stig and returns a list of all techniques in the stig'''
    attack_json = ""
    with open(attack_path, 'rb') as f:
        attack_json = f.read()
        attack_obj = json.loads(attack_json)
        tech_list = []
        #Search through the ATT&CK objects to create a list of the group objects
        for entry in attack_obj["objects"]:
                if  isinstance(entry.get("external_references"), collections.Iterable)  :
                    ext_ref = entry.get("external_references")
                    #foundIndex = findIndexGid(ext_ref)
                    '''if foundIndex != -1:
                        if  ext_ref[foundIndex].get("external_id") is not None and "T" in ext_ref[foundIndex].get("external_id"):
                            #print(ext_ref[0].get("external_id"))'''
                    if "attack-pattern" in entry.get("type"):
                            tech_list.append(entry)
    return tech_list

def grabSoftwareList(attack_path):
    ''' Reads the Enterprise json stig and returns a list of all software in the stig'''
    attack_json = ""
    with open(attack_path, 'rb') as f:
        attack_json = f.read()
        attack_obj = json.loads(attack_json)

        software_list = []
        #Search through the ATT&CK objects to create a list of the group objects
        for entry in attack_obj["objects"]:
                if  isinstance(entry.get("external_references"), collections.Iterable)  :
                    ext_ref = entry.get("external_references")
                    foundIndex = findIndexGid(ext_ref)
                    if foundIndex != -1:
                        if  ext_ref[foundIndex].get("external_id") is not None and "S" in ext_ref[foundIndex].get("external_id"):
                            #print(ext_ref[foundIndex].get("external_id"))
                            software_list.append(entry)
    return software_list

def generateMarkdownFiles(markdown_path, group_list):

    if os.path.isdir(markdown_path):
        print("Group markdown directory is ready")
    else:
        print("Group markdown directory was created")
        os.mkdir(markdown_path)

    ''' Responsible for creating the markdown files for the group pages and the overview page'''
    #Create markdown for the overview
    o_md_file = open(markdown_path+"overview.md", "w", encoding='utf8')
    o_md_file.write("Title: Overview \n")
    o_md_file.write("Template: group_overview \n")
    o_md_file.write("save_as: groups/"+"index.html \n")
    o_md_file.write("Links: {} \n")
    o_md_file.write("Table: {} \n")

    #Create the markdown for the enterprise groups in the stig
    for obj in group_list:
        main_group_title = ""
        descr = ""
        gid = ""
        aliases_list = []
        aliases = ""
        
        if obj.get("name") is not None:
            main_group_title = obj.get("name")
            #print("Title: "+ main_group_title)
            if obj.get("description") is not None:
                descr = obj.get("description")
                #print("Description: "+descr)
            if  isinstance(obj.get("external_references"), collections.Iterable)  :
                ext_ref = obj.get("external_references")
                foundIndex = findIndexGid(ext_ref)
                if foundIndex != -1:
                    if  ext_ref[foundIndex].get("external_id") is not None and "G" in ext_ref[foundIndex].get("external_id"):
                        gid = ext_ref[foundIndex].get("external_id")
                        #print("External ref: "+gid)
            if  isinstance(obj.get("aliases"), collections.Iterable)  :
                aliases_list = obj.get("aliases")
            

            #Read through list of aliases to create one string list of aliases
            ali_count = 0
            while ali_count < len(aliases_list):
                if ali_count == len(aliases_list) - 1:
                    aliases = aliases + aliases_list[ali_count]
                else:
                     aliases = aliases + aliases_list[ali_count]+", "
                ali_count = ali_count + 1
            
            
            
            #Write out the markdown file
            md_file = open(markdown_path+""+gid+".md", "w", encoding='utf8')
            md_file.write("Title: "+main_group_title+"\n")
            md_file.write("Template: group \n")
            md_file.write("ID: "+gid+"\n")
            md_file.write("Aliases: "+aliases+"\n")
            md_file.write("Contributors: {}\n")
            md_file.write("save_as: groups/"+gid.upper()+"/index.html \n")
            md_file.write("Links: {} \n")
            md_file.write("Techniques: {} \n")
            md_file.write("Software: {} \n")
            md_file.write("Bottom_ref: {} \n")
            md_file.write("Description: {} \n")
            md_file.write("Scripts: {} \n")
            md_file.close()


def genLinks(group_list, obj):
    ''' Responsible for generating the links that are located on the left side of group pages'''

    link_template = " <a class=\"nav-link side\" id=\"v-{}-tab\"  href=\"{}\"  aria-controls=\"v-{}\" aria-selected=\"false\">{}</a>"
    active_link_template = " <a class=\"nav-link side active show\" id=\"v-{}-tab\"  href=\"{}\" aria-controls=\"v-{}\" aria-selected=\"false\">{}</a>"
    #Start the formation of link section with overview, and then add the others
    overview_title = "Overview"
    #If the passed obj is overview, generate the overview html variable
    #Else generate the links for the group entry that is passed
    if "overview" in obj.get("name"):
        link_html_var = active_link_template.format(overview_title.lower(), "/groups/", overview_title.lower(), overview_title)+"\n"
        for obj_inner in group_list:
            title = obj_inner.get("name")
            if  isinstance(obj_inner.get("external_references"), collections.Iterable)  :
                ext_ref = obj_inner.get("external_references")
                foundIndex = findIndexGid(ext_ref)
                if foundIndex != -1:
                    if  ext_ref[foundIndex].get("external_id") is not None and "G" in ext_ref[foundIndex].get("external_id") and  obj_inner.get("name") is not None:
                        gid = ext_ref[foundIndex].get("external_id")
                        #create normal links
                        link_html_var = link_html_var + link_template.format(gid.lower(), "/groups/"+gid.upper()+"/", gid.lower(), title)+"\n"
    else:
        link_html_var = link_template.format(overview_title.lower(), "/groups/", overview_title.lower(), overview_title)+"\n"
        for obj_inner in group_list:
            #If the passed object matches the current one in the traversal, create an active link for it
            #Else, will create the links that are not active
            if obj.get("name") == obj_inner.get("name"):
                title = obj_inner.get("name")
                if  isinstance(obj.get("external_references"), collections.Iterable)  :
                    ext_ref = obj.get("external_references")
                    foundIndex = findIndexGid(ext_ref)
                    if foundIndex != -1:
                        if  ext_ref[foundIndex].get("external_id") is not None and "G" in ext_ref[foundIndex].get("external_id") and  obj.get("name") is not None:
                            gid = ext_ref[foundIndex].get("external_id")
                            #create active links
                            link_html_var = link_html_var + active_link_template.format(gid.lower(),  "/groups/"+gid.upper()+"/", gid.lower(), title)+"\n"
            else:
                title = obj_inner.get("name")
                if  isinstance(obj_inner.get("external_references"), collections.Iterable)  :
                    ext_ref = obj_inner.get("external_references")
                    foundIndex = findIndexGid(ext_ref)
                    if foundIndex != -1:
                        if  ext_ref[foundIndex].get("external_id") is not None and "G" in ext_ref[foundIndex].get("external_id") and  obj_inner.get("name") is not None:
                            gid = ext_ref[foundIndex].get("external_id")
                            #create normal links
                            link_html_var = link_html_var + link_template.format(gid.lower(),  "/groups/"+gid.upper()+"/", gid.lower(), title)+"\n"
    return link_html_var




def generate():
   ''' This is the main function called to start generating the markdown files that pelican can make use of for page generation'''
 
   attack_path = "stix/enterprise-attack.json"
   markdown_path = "content/pages/groups/"
   #Reads the json attack stig and creates a list of the ATTACK Groups
   group_list = grabGroupList(attack_path)
   #Generates the markdown files to be used for page generation
   generateMarkdownFiles(markdown_path, group_list)
   print("Finished generating the group markdwown")


def updateLinkSections():
    '''  The main function used to load dynamic links, and tables into the pages created by pelican'''
    ent_attack_path = "stix/enterprise-attack.json"
    mob_attack_path = "stix/mobile-attack.json"
    pre_attack_path = "stix/pre-attack.json"
    html_path = "output/groups/"
    #Reads the json attack stig and creates a list of the ATTACK Groups
    group_list = grabGroupList(ent_attack_path)
    technique_list = grabTechniqueList(ent_attack_path)
    #Generate the technique table for the right sections and assign to variable
    tech_table_dict = generateTechniqueTable()
    #Generate the software table
    gen_soft_dict = generateSoftwareTable()

    #Generate the needed html sections for links and tables
    for obj in group_list:
        main_group_title = ""
        contributors_list = []
        
        descr = ""
        gid = ""
        ext_ref_obj = None
        if obj.get("name") is not None:
            main_group_title = obj.get("name")

            
            if isinstance(obj.get("x_mitre_contributors"), collections.Iterable)  :
                contributors_list = obj.get("x_mitre_contributors")


            #print("Title: "+ main_group_title)
            if obj.get("description") is not None:
                descr = obj.get("description")
            if obj.get("external_references") is not None:
                ext_ref_obj = obj.get("external_references") 
            if  isinstance(obj.get("external_references"), collections.Iterable)  :
                ext_ref = obj.get("external_references")
                foundIndex = findIndexGid(ext_ref)
                if foundIndex != -1:
                    if  len(ext_ref) > 0 and ext_ref[foundIndex].get("external_id") is not None and "G" in ext_ref[foundIndex].get("external_id"):
                        gid = ext_ref[foundIndex].get("external_id")
                        #print("External ref: "+gid)

                        #Generate the links needed for the left section and assign to variable
                        generated_links = genLinks(group_list, obj)

                        #Generate the contributors section
                        generated_contributors_sect = gen_contr_sect(contributors_list)
                        #Grab the entry from technique dict that will be use for technique table html
                        generated_technique_table = tech_table_dict.get(gid)

                        #Grab the entry from software dict that will be used for software table html
                        generated_software_table = gen_soft_dict.get(gid)

                        generated_references_list = gen_ref_list(descr,ext_ref)#Grabs citations and urls from description
                        # Will make it so these are merged with the description field
                        description_ref_section = gen_descr_ref_sect(generated_references_list, descr)
                        

                        generated_refs_bottom_sect = gen_ref_bottom_sect(generated_references_list)
                        js_Scripts = ""#genScripts(len(generated_references_list))
                        #Save the generated areas into the placeholders
                        html_file = open(html_path+gid.upper()+"/index.html", "r")
                        html_content = html_file.read()
                        new_html = html_content.format(generated_links,description_ref_section,generated_contributors_sect, generated_technique_table, generated_software_table, generated_refs_bottom_sect,js_Scripts)
                        html_file.close()

                        new_html_file = open(html_path+gid.upper()+"/index.html", "w", encoding='utf8')
                        new_html_file.write(new_html)
                        new_html_file.close()

    #Now focus on generating the overview page
    #first the links on the left
    overview_dict = {"name":"overview"}
    generated_links = genLinks(group_list, overview_dict)
    html_file = open(html_path+"index.html", "r")
    html_content = html_file.read()
    

    overview_table_v = ""
    #Now the table on the right, which is made up of group data
    for obj in group_list:
        main_group_title = ""
        descr = ""
        gid = ""
        aliases_list = []
        aliases = ""
        if obj.get("name") is not None:
            main_group_title = obj.get("name")
            #print("Title: "+ main_group_title)
            if obj.get("description") is not None:
                descr = obj.get("description")
                
                #print("Description: "+descr)
            if  isinstance(obj.get("external_references"), collections.Iterable)  :
                ext_ref = obj.get("external_references")
                foundIndex = findIndexGid(ext_ref)
                if foundIndex != -1:
                    if  ext_ref[foundIndex].get("external_id") is not None and "G" in ext_ref[foundIndex].get("external_id"):
                        gid = ext_ref[foundIndex].get("external_id")
                        #print("External ref: "+gid)
            if  isinstance(obj.get("aliases"), collections.Iterable)  :
                aliases_list = obj.get("aliases")

            #Read through list of alises to create one string list of aliases
            ali_count = 0
            while ali_count < len(aliases_list):
                if ali_count == len(aliases_list) - 1:
                    aliases = aliases + aliases_list[ali_count]
                else:
                     aliases = aliases + aliases_list[ali_count]+", <br> "
                ali_count = ali_count + 1
            
            top_row_v = "<tr><td><a href=\"/groups/"+gid.upper()+"/\">"+main_group_title+"</a></td>"
            middle_row_v = "<td>"+aliases+"</td>"
            end_row_v = "<td>"+descr+"</td></tr>"
            overview_table_v = overview_table_v +"\n"+top_row_v+"\n"+middle_row_v+"\n"+end_row_v+"\n"
            

            #push the generated sections into the respective placeholder areas
            new_html = html_content.format(generated_links, overview_table_v)
            html_file.close()
            #Save the new version with updated links
            new_html_file = open(html_path+"index.html", "w", encoding='utf8')
            new_html_file.write(new_html)
            new_html_file.close()
    print("Finished updating group html files")

def grabRelationship(attack_path, option):
    ''' Focuses on grabbing the relationships between Group and Technique, Group and Software, and Software and Technique'''
    attack_json = ""
    #Reads the Enterprise stig to extract the relationship ojects, and returns them in a list
    with open(attack_path, 'rb') as f:
        attack_json = f.read()
        attack_obj = json.loads(attack_json)

        group_rel_list = []
        #Search through the ATT&CK objects to create a list of the group objects
        for entry in attack_obj["objects"]:
            if "GT" in option: #handles group to technique
                if entry.get("source_ref") is not None and "intrusion-set" in entry.get("source_ref") and entry.get("relationship_type") is not None and  "uses" in entry.get("relationship_type") and entry.get("target_ref") is not None and  "attack-pattern" in entry.get("target_ref"):
                    group_rel_list.append(entry)
            elif "GS" in option:#handles group to software
                if entry.get("source_ref") is not None and "intrusion-set" in entry.get("source_ref") and entry.get("relationship_type") is not None and  "uses" in entry.get("relationship_type") and entry.get("target_ref") is not None and  "malware" in entry.get("target_ref"):
                    group_rel_list.append(entry)
            elif "ST" in option:#software to technique
                if entry.get("source_ref") is not None and "malware" in entry.get("source_ref") and entry.get("relationship_type") is not None and  "uses" in entry.get("relationship_type") and entry.get("target_ref") is not None and  "attack-pattern" in entry.get("target_ref"):
                    group_rel_list.append(entry)            
    return group_rel_list

def generateTechniqueTable():
    ''' This function creates a dictionary of all the relationships linked that are needed for the technique table'''
    techniqueOuterTemp = "<h2 class=\"pt-3\" id =\"techniques\">Techniques Used</h2>" + "<table class=\"table table-bordered table-light mt-2\">" + "<thead><tr> <th scope=\"col\">Domain</th><th scope=\"col\">ID</th><th scope=\"col\">Name</th><th scope=\"col\">Use</th>" +"  </tr></thead><tbody> {} </tbody></table>"
    table_dict = {}
    ent_attack_path = "stix/enterprise-attack.json"
    mob_attack_path = "stix/mobile-attack.json"
    pre_attack_path = "stix/pre-attack.json"
    attack_json = ""
    #grab a list of techniques, groups, and relationships from attack stig for enterprise attack
    tech_list = grabTechniqueList(ent_attack_path)
    rel_list = grabRelationship(ent_attack_path, "GT")
    group_list = grabGroupList(ent_attack_path)

    mob_tech_list = grabTechniqueList(mob_attack_path)
    mob_rel_list = grabRelationship(mob_attack_path, "GT")
    mob_group_list = grabGroupList(mob_attack_path)
    
    pre_tech_list = grabTechniqueList(pre_attack_path)
    pre_rel_list = grabRelationship(pre_attack_path, "GT")
    pre_group_list = grabGroupList(pre_attack_path)

    group_list = group_list + mob_group_list + pre_group_list
    tech_list = tech_list + mob_tech_list + pre_tech_list
    rel_list = rel_list + mob_rel_list + pre_rel_list
    #Go to each group
    for group in group_list:
        #print(group.get("external_references")[0].get("external_id"))
        list_of_group_techniques = []
        #find the relationships for each group
        for rel in rel_list:
            if group.get("id") in rel.get("source_ref"):
                # print("Techniques used for: "+group.get("external_references")[0].get("external_id"))
                #Use those relationships to find the technique that affects the group
                for tech in tech_list:
                    if rel.get("target_ref") in tech.get("id"):
                        #print(tech.get("external_references")[0].get("external_id"))
                        #print(tech.get("description"))
                        tech_rel_dict = {"tech": tech, "rel":rel}
                        list_of_group_techniques.append(tech_rel_dict)
        #Create the html version of the table for the Techniques
        technique_table = ""
        flag = False
        for logt in list_of_group_techniques:
            description = ""
            if logt.get("rel").get("description") is not None:
                description = logt.get("rel").get("description")
            domain = mapDomain(logt.get("tech").get("kill_chain_phases")[0].get("kill_chain_name"))
            flag = True
            foundIndex = findIndexGid(logt.get("tech").get("external_references"))
            if foundIndex != -1:
                tr_row_1 = "<tr><td>"+domain +"</td><td><a href=\"/techniques/"+logt.get("tech").get("external_references")[foundIndex].get("external_id")+"/\">"+logt.get("tech").get("external_references")[foundIndex].get("external_id")+"</a></td>"
                tr_row_2 = "<td><a href=\"/techniques/"+logt.get("tech").get("external_references")[foundIndex].get("external_id")+"/\">"+logt.get("tech").get("name")+"</a></td>"
                tr_row_3 = "<td>"+description+"</td></tr>"
                technique_table = technique_table + tr_row_1 + tr_row_2 + tr_row_3
        if flag:
            foundIndex = findIndexGid(group.get("external_references"))
            if foundIndex != -1:
                table_dict[group.get("external_references")[foundIndex].get("external_id")] = techniqueOuterTemp.format(technique_table)
        else:
            foundIndex = findIndexGid(group.get("external_references"))
            if foundIndex != -1:
                table_dict[group.get("external_references")[foundIndex].get("external_id")] = ""
    return table_dict

def generateSoftwareTable():
    ''' This is responsible for generating the software html table '''
    softwareOuterTemplate = "<h2 class=\"pt-3\" id=\"software\"  >Software</h2><table class=\"table table-bordered table-light mt-2\"><thead><tr><th scope=\"col\">ID</th><th scope=\"col\">Name</th><th scope=\"col\">Techniques</th></tr></thead><tbody> {}"+" </tbody></table>"


    table_dict = {}
    attack_path = "stix/enterprise-attack.json"
    attack_json = ""
    tech_list = grabTechniqueList(attack_path)
    gs_rel_list = grabRelationship(attack_path, "GS")
    st_rel_list = grabRelationship(attack_path, "ST")
    group_list = grabGroupList(attack_path)
    software_list = grabSoftwareList(attack_path)
    
    #Traverse the list of groups, and generate the software table in the form of a dict that as the software to technique mapping too
    for group in group_list:
        
        list_of_group_software = []
        
        for gs_rel in gs_rel_list:
            #completes linking for group to group-to-software relationship
            if group.get("id") in gs_rel.get("source_ref"):
                #print("Techniques used for: "+group.get("external_references")[0].get("external_id"))
                for software in software_list:
                    techniq_mapped_list = []
                    dict_software_tech = {}
                    #completes linking for group-to-software relationship to software
                    if gs_rel.get("target_ref") in software.get("id"): 
                       
                        list_of_group_software.append(software)
                        
                        for st_rel in st_rel_list:
                            #completes linking for software to software-to-technique relationship
                            if software.get("id") in st_rel.get("source_ref"):

                                for technique in tech_list:
                                    #completes linking for software-to-technique relationship to technique
                                    if st_rel.get("target_ref") in technique.get("id"):
                                        techniq_mapped_list.append(technique)
                        
                        dict_software_tech = {"software":software, "mapped_techs": techniq_mapped_list}
                        list_of_group_software.append(dict_software_tech)

        #Create the html version of the table for the Software
        software_table = ""
        flag = False
        for soft_dict in list_of_group_software:
            flag = True
            #create a string of techniques
            tech_string = ""
            count_tech = 0
            if soft_dict.get("mapped_techs") is not None:
                temp_tech_array = soft_dict.get("mapped_techs")
                while count_tech < len(temp_tech_array):
                    if count_tech == len(temp_tech_array) - 1:
                        tech_string = tech_string + temp_tech_array[count_tech].get("name")
                    else:
                        tech_string = tech_string + temp_tech_array[count_tech].get("name")+", "
                    count_tech = + count_tech + 1
            if soft_dict.get("software") is not None:
                foundIndex = findIndexGid(soft_dict.get("software").get("external_references"))
                if foundIndex != -1:
                    tr_row_1 = "<tr><td><a href=\"/software/"+soft_dict.get("software").get("external_references")[foundIndex].get("external_id")+"/\">"+soft_dict.get("software").get("external_references")[foundIndex].get("external_id")+"</a></td>"
                    tr_row_2 = "<td><a href=\"/software/"+soft_dict.get("software").get("external_references")[foundIndex].get("external_id")+"/\">"+soft_dict.get("software").get("name")+"</a></td>"
                    tr_row_3 = "<td>"+tech_string+"</td></tr>"
                    software_table = software_table + tr_row_1 + tr_row_2 + tr_row_3
        #Store the generated html data to a dict that can be queried based on gid
        if flag:
            foundIndex = findIndexGid(group.get("external_references"))
            if foundIndex != -1:
                table_dict[group.get("external_references")[foundIndex].get("external_id")] = softwareOuterTemplate.format(software_table)
        else:
            foundIndex = findIndexGid(group.get("external_references"))
            if foundIndex != -1:
                table_dict[group.get("external_references")[foundIndex].get("external_id")] = ""
    return table_dict

def mapDomain(text):
    if text in "mitre-mobile-attack":
        return "Mobile"
    elif text in "mitre-attack":
        return "Enterprise"
    elif text in "mitre-pre-attack":
        return "Pre-Attack"
    else:
        return "None"

def gen_ref_list(description, ext_ref):
    if description is not None and ext_ref is not None:
        counter = 0
        descr_count = 1
        array_citation_sname = []
        while counter < len(description):
            if counter < len(description) - 12:
                if "(Citation: " in description[counter:counter+11]:
                    end_count = counter+11
                    while ")" not in description[end_count]:
                        end_count = end_count + 1
                    #print(description[counter+11:end_count])
                    descr_dict = {"number":descr_count, "sname": description[counter+11:end_count]}
                    array_citation_sname.append(descr_dict)
                    descr_count = descr_count + 1
            counter = counter + 1
    #print(str(array_citation_sname))
    temp_c_s_array = []
    #remove duplicates
    count_non_dup = 2
    for obj in array_citation_sname:
        if len(temp_c_s_array) == 0:
            obj["number"] = 1
            temp_c_s_array.append(obj)
        else:
            flag = False
            for obj2 in temp_c_s_array:
                if obj.get("sname") in obj2.get("sname"):
                    flag = True
            if not flag:
                obj["number"] = count_non_dup
                temp_c_s_array.append(obj)
                count_non_dup = count_non_dup + 1
    array_citation_sname = temp_c_s_array

    #array_citation_sname = list(set(array_citation_sname))
    #print(str(array_citation_sname))
    url_list = []
    for desc_obj in array_citation_sname:
        link = None
        for ext in ext_ref:
            if desc_obj.get("sname") is not None and ext.get("source_name") is not None and desc_obj.get("sname") in ext.get("source_name"):
                link = ext.get("url")
                url_dict = {"number":desc_obj.get("number"), "url": link, "sname":desc_obj.get("sname"),  "description":ext.get("description")}
                url_list.append(url_dict)
    #print("URL list: "+str(url_list))
    return url_list

def gen_descr_ref_sect(url_list, description):
    top_span_template = "<span onclick=scrollToRef('scite-{}')  id=\"scite-ref-{}-a\" class=\"scite-citeref-number\" data-reference=\"{}\"><a href=\"{}\" data-hasqtip=\"{}\" aria-describedby=\"qtip-{}\">[{}]</a></span>"
    list_of_top_sects = []
    top_sect = ""
    for url_obj in url_list:
        number = url_obj.get("number")
        sname = url_obj.get("sname")
        url = url_obj.get("url")
        sect = top_span_template.format(number,number,sname,url,number - 1, number - 1, number)
        counter = 0
        while counter < len(description):
            if counter < len(description) - 12:
                if "(Citation: " in description[counter:counter+11]:
                    end_count = counter+11
                    while ")" not in description[end_count]:
                        end_count = end_count + 1
                    #print(description[counter:end_count+1])
                    if sname  in description[counter:end_count]:
                        description = description.replace(description[counter:end_count+1], sect)
            counter = counter + 1
    counter_contr = 0
    while counter_contr < len(description):
        if counter_contr < len(description) - 14:
            if "Contributors:" in description[counter_contr:counter_contr+14]:
                description = description.replace(description[counter_contr:len(description)], " ")
                counter_contr = len(description)
        counter_contr = counter_contr + 1
    
    return description

def gen_ref_bottom_sect(url_list):
    div_row = "<div class=\"row\">{}</div>"
    div_temp = "<div class=\"col\">{} </div>"
    ol_temp = "<ol>{}</ol>"
    ol_start_temp = "<ol start=\"{}\">{}</ol>"
    bottom_span_template = "<li><span  id=\"scite-{}\" class=\"scite-citation\"><span class=\"scite-citation-text\"><a rel=\"nofollow\" class=\"external text\" name=\"scite-{}\" href=\"{}\">{}</a></span></span></li>"
    list_of_bottom_sects = []
    bottom_sect_l = ""
    bottom_sect_r = ""
    bottom_sect_dict = {"left":"", "right":""}
    for url_obj in url_list:
                number = url_obj.get("number")
                sname = url_obj.get("sname")
                url = url_obj.get("url")
                description = url_obj.get("description")
                sect = bottom_span_template.format(number,number,url,description)
                
                list_of_bottom_sects.append(sect)
    count = 0
    while count < len(list_of_bottom_sects):
            bottom_s = list_of_bottom_sects[count]
            
            if count < len(list_of_bottom_sects) / 2:
                bottom_sect_l = bottom_sect_l + bottom_s
            else:
                bottom_sect_r = bottom_sect_r + bottom_s
            count = count + 1
    if len(url_list) <= 1:

        right_div = div_temp.format("")
        bottom_sect_dict["right"] = right_div
        left_ol = ol_temp.format(bottom_sect_l)
        left_div = div_temp.format(left_ol)
        bottom_sect_dict["left"] = left_div
    else:
        
        left_ol = ol_temp.format(bottom_sect_l)
        left_div = div_temp.format(left_ol)
        if len(list_of_bottom_sects) % 2 == 0:
            right_ol = ol_start_temp.format(str(len(list_of_bottom_sects) / 2 + 1), bottom_sect_r)
        else:
            right_ol = ol_start_temp.format(str(len(list_of_bottom_sects) / 2 + 2), bottom_sect_r)
        right_div = div_temp.format(right_ol)
      
        bottom_sect_dict["left"] = left_div
        bottom_sect_dict["right"] = right_div
    
    
    return div_row.format(bottom_sect_dict.get("left") + bottom_sect_dict.get("right"))
   

def genScripts(totalRefs):
    #Not Used
    '''Generates scripts that will ensure that the group page functions properly'''
    scriptTemplate = "<script>{}</script>"

    funcScroll = "function scrollToRef(val){  var element_to_scroll_to = document.getElementById(val); var origcolor = element_to_scroll_to.style.backgroundColor; var totalRefs="+str(totalRefs)+"; var count = 1; while(count <= totalRefs){ document.getElementById('scite-'+count).style.backgroundColor = origcolor; count++; }  element_to_scroll_to.scrollIntoView();  element_to_scroll_to.style.backgroundColor = 'yellow'; }"
    readyScript = scriptTemplate.format(funcScroll)
    return readyScript

def gen_contr_sect(contr_list):

    if len(contr_list) == 0:
        return ""
    else:
        contributors = ""
        contr_count = 0
        while contr_count < len(contr_list):
            if contr_count == len(contr_list) - 1:
                contributors = contributors + contr_list[contr_count]
            else:
                contributors = contributors + contr_list[contr_count]+", "
            contr_count = contr_count + 1
        
        sect =  "<span class=\"h5 card-title\">Contributors</span>: "+contributors
        return sect 
