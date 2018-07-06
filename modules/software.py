import os, json, collections

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
                    foundIndex = findIndexSid(ext_ref)
                    if foundIndex != -1:
                        if  ext_ref[foundIndex].get("external_id") is not None and "S" in ext_ref[foundIndex].get("external_id"):
                            #print(ext_ref[foundIndex].get("external_id"))
                            software_list.append(entry)
    return software_list

def findIndexSid(ext_ref):
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

def generate():
   ''' This is the main function called to start generating the markdown files that pelican can make use of for software page generation'''
 
   attack_path = "stix/enterprise-attack.json"
   markdown_path = "content/pages/software/"
   #Reads the json attack stig and creates a list of the ATTACK Groups
   software_list = grabSoftwareList(attack_path)
   #Generates the markdown files to be used for page generation
   generateMarkdownFiles(markdown_path, software_list)
   print("Finished generating the software markdwown")


def generateMarkdownFiles(markdown_path, software_list):

    if os.path.isdir(markdown_path):
        print("Software markdown directory is ready")
    else:
        print("Software markdown directory was created")
        os.mkdir(markdown_path)

    ''' Responsible for creating the markdown files for the software pages and the overview page'''
    #Create markdown for the overview
    o_md_file = open(markdown_path+"overview.md", "w", encoding='utf8')
    o_md_file.write("Title: Overview \n")
    o_md_file.write("Template: software_overview \n")
    o_md_file.write("save_as: software/"+"index.html \n")
    o_md_file.write("Links: {} \n")
    o_md_file.write("Table: {} \n")

    #Create the markdown for the enterprise groups in the stig
    for obj in software_list:
        main_software_title = ""
        descr = ""
        sid = ""
        aliases_list = []
        aliases = ""
        
        if obj.get("name") is not None:
            main_software_title = obj.get("name")
            #print("Title: "+ main_software_title)
            if obj.get("description") is not None:
                descr = obj.get("description")
                #print("Description: "+descr)
            if  isinstance(obj.get("external_references"), collections.Iterable)  :
                ext_ref = obj.get("external_references")
                foundIndex = findIndexSid(ext_ref)
                if foundIndex != -1:
                    if  ext_ref[foundIndex].get("external_id") is not None and "S" in ext_ref[foundIndex].get("external_id"):
                        sid = ext_ref[foundIndex].get("external_id")
                        #print("External ref: "+sid)
            if  isinstance(obj.get("x_mitre_aliases"), collections.Iterable)  :
                aliases_list = obj.get("x_mitre_aliases")
            

            #Read through list of aliases to create one string list of aliases
            ali_count = 0
            while ali_count < len(aliases_list):
                if ali_count == len(aliases_list) - 1:
                    aliases = aliases + aliases_list[ali_count]
                else:
                     aliases = aliases + aliases_list[ali_count]+", "
                ali_count = ali_count + 1
            
            #Write out the markdown file
            md_file = open(markdown_path+""+sid+".md", "w", encoding='utf8')
            md_file.write("Title: "+main_software_title+"\n")
            md_file.write("Template: software \n")
            md_file.write("ID: "+sid+"\n")
            md_file.write("Aliases: "+aliases+"\n")
            #md_file.write("Contributors: {}\n")
            md_file.write("save_as: software/"+sid.upper()+"/index.html \n")
            md_file.write("Links: {} \n")
            md_file.write("Techniques: {} \n")
            #md_file.write("Groups: {} \n")
            md_file.write("Bottom_ref: {} \n")
            md_file.write("Description: {} \n")
            #md_file.write("Scripts: {} \n")
            md_file.close()


def updateLinkSections():
    '''  The main function used to load dynamic links, and tables into the pages created by pelican'''
    ent_attack_path = "stix/enterprise-attack.json"
    mob_attack_path = "stix/mobile-attack.json"
    pre_attack_path = "stix/pre-attack.json"
    html_path = "output/software/"
    #Reads the json attack stig and creates a list of the ATTACK Groups
    #--group_list = grabGroupList(ent_attack_path)
    software_list = grabSoftwareList(ent_attack_path)
    technique_list = grabTechniqueList(ent_attack_path)
    #Generate the technique table for the right sections and assign to variable
    tech_table_dict = generateTechniqueTable()
    #Generate the software table
    #gen_soft_dict = generateSoftwareTable()

    #Generate the needed html sections for links and tables for software
    for obj in software_list:
        main_software_title = ""
        contributors_list = []
        
        descr = ""
        sid = ""
        ext_ref_obj = None
        if obj.get("name") is not None:
            main_software_title = obj.get("name")

            
            if isinstance(obj.get("x_mitre_contributors"), collections.Iterable)  :
                contributors_list = obj.get("x_mitre_contributors")


            #print("Title: "+ main_software_title)
            if obj.get("description") is not None:
                descr = obj.get("description")

                #Read through list of aliases to create one string list of aliases
                #Then, remove the aliases part from the description string
                aliases_list = []
                aliases = ""
                if  isinstance(obj.get("x_mitre_aliases"), collections.Iterable)  :
                    aliases_list = obj.get("x_mitre_aliases")
                    ali_count = 0
                    while ali_count < len(aliases_list):
                        if ali_count == len(aliases_list) - 1:
                            aliases = aliases + aliases_list[ali_count]
                        else:
                            aliases = aliases + aliases_list[ali_count]+", "
                        ali_count = ali_count + 1
                    rep_str = "\n\nAliases: "+aliases
                    descr = descr.replace(rep_str, "")
                    #Remove any that escaped
                    descr = descr.replace("Aliases:", "")
                  
            if obj.get("external_references") is not None:
                ext_ref_obj = obj.get("external_references") 
            if  isinstance(obj.get("external_references"), collections.Iterable)  :
                ext_ref = obj.get("external_references")
                foundIndex = findIndexSid(ext_ref)
                if foundIndex != -1:
                    if  len(ext_ref) > 0 and ext_ref[foundIndex].get("external_id") is not None and "S" in ext_ref[foundIndex].get("external_id"):
                        sid = ext_ref[foundIndex].get("external_id")
                        #print("External ref: "+sid)

                        #Generate the links needed for the left section and assign to variable
                        generated_links = genLinks(software_list, obj)

                        #Generate the contributors section
                        #--generated_contributors_sect = gen_contr_sect(contributors_list)
                        #Grab the entry from technique dict that will be use for technique table html
                        generated_technique_table = tech_table_dict.get(sid)

                        #Grab the entry from software dict that will be used for software table html
                        #--generated_software_table = gen_soft_dict.get(sid)

                        generated_references_list = gen_ref_list(descr,ext_ref)#Grabs citations and urls from description
                        # Will make it so these are merged with the description field
                        description_ref_section = gen_descr_ref_sect(generated_references_list, descr)
                        

                        generated_refs_bottom_sect = gen_ref_bottom_sect(generated_references_list)
                        
                        #Save the generated areas into the placeholders
                        html_file = open(html_path+sid.upper()+"/index.html", "r")
                        html_content = html_file.read()
                        new_html = html_content.format(generated_links,description_ref_section, generated_technique_table, generated_refs_bottom_sect)
                        html_file.close()

                        new_html_file = open(html_path+sid.upper()+"/index.html", "w", encoding='utf8')
                        new_html_file.write(new_html)
                        new_html_file.close()

    #Now focus on generating the overview page
    #first the links on the left
    overview_dict = {"name":"overview"}
    generated_links = genLinks(software_list, overview_dict)
    html_file = open(html_path+"index.html", "r")
    html_content = html_file.read()
    

    overview_table_v = ""
    #Now the table on the right, which is made up of group data
    for obj in software_list:
        main_software_title = ""
        descr = ""
        sid = ""
        aliases_list = []
        aliases = ""
        if obj.get("name") is not None:
            main_software_title = obj.get("name")
            #print("Title: "+ main_software_title)
            if obj.get("description") is not None:
                descr = obj.get("description")
                
                #print("Description: "+descr)
            if  isinstance(obj.get("external_references"), collections.Iterable)  :
                ext_ref = obj.get("external_references")
                foundIndex = findIndexSid(ext_ref)
                if foundIndex != -1:
                    if  ext_ref[foundIndex].get("external_id") is not None and "S" in ext_ref[foundIndex].get("external_id"):
                        sid = ext_ref[foundIndex].get("external_id")
                        #print("External ref: "+sid)
            if  isinstance(obj.get("x_mitre_aliases"), collections.Iterable)  :
                aliases_list = obj.get("x_mitre_aliases")

            #Read through list of alises to create one string list of aliases
            ali_count = 0
            while ali_count < len(aliases_list):
                if ali_count == len(aliases_list) - 1:
                    aliases = aliases + aliases_list[ali_count]
                else:
                     aliases = aliases + aliases_list[ali_count]+", <br> "
                ali_count = ali_count + 1
            
            top_row_v = "<tr><td><a href=\""+sid.upper()+"/\">"+main_software_title+"</a></td>"
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
    print("Finished updating software html files")

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

def genLinks(software_list, obj):
    ''' Responsible for generating the links that are located on the left side of software pages'''

    link_template = " <a class=\"nav-link side\" id=\"v-{}-tab\"  href=\"{}\"  aria-controls=\"v-{}\" aria-selected=\"false\">{}</a>"
    active_link_template = " <a class=\"nav-link side active show\" id=\"v-{}-tab\"  href=\"{}\" aria-controls=\"v-{}\" aria-selected=\"false\">{}</a>"
    #Start the formation of link section with overview, and then add the others
    overview_title = "Overview"
    #If the passed obj is overview, generate the overview html variable
    #Else generate the links for the group entry that is passed
    if "overview" in obj.get("name"):
        link_html_var = active_link_template.format(overview_title.lower(), "/software/", overview_title.lower(), overview_title)+"\n"
        for obj_inner in software_list:
            title = obj_inner.get("name")
            if  isinstance(obj_inner.get("external_references"), collections.Iterable)  :
                ext_ref = obj_inner.get("external_references")
                foundIndex = findIndexSid(ext_ref)
                if foundIndex != -1:
                    if  ext_ref[foundIndex].get("external_id") is not None and "S" in ext_ref[foundIndex].get("external_id") and  obj_inner.get("name") is not None:
                        sid = ext_ref[foundIndex].get("external_id")
                        #create normal links
                        link_html_var = link_html_var + link_template.format(sid.lower(), "/software/"+sid.upper()+"/", sid.lower(), title)+"\n"
    else:
        link_html_var = link_template.format(overview_title.lower(), "/software/", overview_title.lower(), overview_title)+"\n"
        for obj_inner in software_list:
            #If the passed object matches the current one in the traversal, create an active link for it
            #Else, will create the links that are not active
            if obj.get("name") == obj_inner.get("name"):
                title = obj_inner.get("name")
                if  isinstance(obj.get("external_references"), collections.Iterable)  :
                    ext_ref = obj.get("external_references")
                    foundIndex = findIndexSid(ext_ref)
                    if foundIndex != -1:
                        if  ext_ref[foundIndex].get("external_id") is not None and "S" in ext_ref[foundIndex].get("external_id") and  obj.get("name") is not None:
                            sid = ext_ref[foundIndex].get("external_id")
                            #create active links
                            link_html_var = link_html_var + active_link_template.format(sid.lower(), "/software/"+sid.upper()+"/", sid.lower(), title)+"\n"
            else:
                title = obj_inner.get("name")
                if  isinstance(obj_inner.get("external_references"), collections.Iterable)  :
                    ext_ref = obj_inner.get("external_references")
                    foundIndex = findIndexSid(ext_ref)
                    if foundIndex != -1:
                        if  ext_ref[foundIndex].get("external_id") is not None and "S" in ext_ref[foundIndex].get("external_id") and  obj_inner.get("name") is not None:
                            sid = ext_ref[foundIndex].get("external_id")
                            #create normal links
                            link_html_var = link_html_var + link_template.format(sid.lower(), "/software/"+sid.upper()+"/", sid.lower(), title)+"\n"
    return link_html_var

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
                    #foundIndex = findIndexSid(ext_ref)
                    '''if foundIndex != -1:
                        if  ext_ref[foundIndex].get("external_id") is not None and "T" in ext_ref[foundIndex].get("external_id"):
                            #print(ext_ref[0].get("external_id"))'''
                    if "attack-pattern" in entry.get("type"):
                            tech_list.append(entry)
    return tech_list

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
    techniqueOuterTemp = "<h2 class=\"pt-3\" id=\"techniques\">Techniques Used</h2>" + "<table class=\"table table-bordered table-light mt-2\">" + "<thead><tr> <th scope=\"col\">ID</th><th scope=\"col\">Name</th><th scope=\"col\">Use</th>" +"  </tr></thead><tbody> {} </tbody></table>"
    table_dict = {}
    ent_attack_path = "stix/enterprise-attack.json"
    mob_attack_path = "stix/mobile-attack.json"
    pre_attack_path = "stix/pre-attack.json"
    attack_json = ""
    #grab a list of techniques, groups, and relationships from attack stig for enterprise attack
    tech_list = grabTechniqueList(ent_attack_path)
    rel_list = grabRelationship(ent_attack_path, "ST")
    software_list = grabSoftwareList(ent_attack_path)

    mob_tech_list = grabTechniqueList(mob_attack_path)
    mob_rel_list = grabRelationship(mob_attack_path, "ST")
    mob_software_list = grabSoftwareList(mob_attack_path)
    
    pre_tech_list = grabTechniqueList(pre_attack_path)
    pre_rel_list = grabRelationship(pre_attack_path, "ST")
    pre_software_list = grabSoftwareList(pre_attack_path)

    software_list = software_list + mob_software_list + pre_software_list
    tech_list = tech_list + mob_tech_list + pre_tech_list
    rel_list = rel_list + mob_rel_list + pre_rel_list
    #Go to each group
    for software in software_list:
        #print(group.get("external_references")[0].get("external_id"))
        list_of_software_techniques = []
        #find the relationships for each group
        for rel in rel_list:
            if software.get("id") in rel.get("source_ref"):
                # print("Techniques used for: "+group.get("external_references")[0].get("external_id"))
                #Use those relationships to find the technique that affects the group
                for tech in tech_list:
                    if rel.get("target_ref") in tech.get("id"):
                        #print(tech.get("external_references")[0].get("external_id"))
                        #print(tech.get("description"))
                        tech_rel_dict = {"tech": tech, "rel":rel}
                        list_of_software_techniques.append(tech_rel_dict)
        #Create the html version of the table for the Techniques
        technique_table = ""
        flag = False
        for lost in list_of_software_techniques:
            description = ""
            if lost.get("rel").get("description") is not None:
                description = lost.get("rel").get("description")
            #domain = mapDomain(lost.get("tech").get("kill_chain_phases")[0].get("kill_chain_name"))
            flag = True
            foundIndex = findIndexSid(lost.get("tech").get("external_references"))
            if foundIndex != -1:
                tr_row_1 = "<tr><td><a href=\"/techniques/"+lost.get("tech").get("external_references")[foundIndex].get("external_id")+"/\">"+lost.get("tech").get("external_references")[foundIndex].get("external_id")+"</a></td>"
                tr_row_2 = "<td><a href=\"/techniques/"+lost.get("tech").get("external_references")[foundIndex].get("external_id")+"/\">"+lost.get("tech").get("name")+"</a></td>"
                tr_row_3 = "<td>"+description+"</td></tr>"
                technique_table = technique_table + tr_row_1 + tr_row_2 + tr_row_3
        if flag:
            foundIndex = findIndexSid(software.get("external_references"))
            if foundIndex != -1:
                table_dict[software.get("external_references")[foundIndex].get("external_id")] = techniqueOuterTemp.format(technique_table)
        else:
            foundIndex = findIndexSid(software.get("external_references"))
            if foundIndex != -1:
                table_dict[software.get("external_references")[foundIndex].get("external_id")] = ""
    return table_dict
