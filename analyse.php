#!/usr/bin/env php
<?php

$g_resolved=array();

function init_cache_resolved()
{
    global $g_resolved;
    $json=file_get_contents("resolved_cache.json");
    $g_resolved=json_decode($json, true);
}

function save_cache_resolved()
{
    global $g_resolved;
    $json=json_encode($g_resolved);
    file_put_contents("resolved_cache.json", $json);
}

init_cache_resolved();

function display_record($new_record, $max_ip_length=20)
{
    global $g_resolved;
    $dkim=$new_record->row->policy_evaluated->dkim;
    if($dkim=="fail")
        $dkim_color="\033[31m";
    else
        $dkim_color="\033[32m";
    $spf=$new_record->row->policy_evaluated->spf;
    if($spf=="fail")
        $spf_color="\033[31m";
    else
        $spf_color="\033[32m";
    
    $source_ip=sprintf("%s",$new_record->row->source_ip);
    if(!isset($g_resolved[$source_ip]))
        $g_resolved[$source_ip] = gethostbyaddr($source_ip);
    
    printf("\t%-5s mails reported : DKIM: %s%s\033[39m SPF: %s%s\033[39m  VIA %".$max_ip_length."s resolved as %s",
        $new_record->row->count,
        $dkim_color,$dkim,
        $spf_color,$spf,
        $source_ip,
        $g_resolved[$source_ip],
        );
    if(strlen($new_record->identifiers->envelope_to)>1)
        printf("\tTO %s\n",$new_record->identifiers->envelope_to);
    else
        printf("\n");
}

if ($handle = opendir('.')) 
{
    $results=array();
    $max_ip_length=0;

    while (false !== ($entry = readdir($handle))) 
    {
        if ($entry != "." && $entry != "..") 
        {
            echo "\n==> $entry\n";
            $zip = new ZipArchive;
            $res = $zip->open($entry);
            // pour les fichiers ZIP
            if ($res === TRUE) 
            {
                $content = file_get_contents("zip://$entry#".$zip->statIndex(0)["name"]);
                $zip->close();
            }
            else
            {
                // pour les fichiers GZ et non compressés
                ob_start(); // Start output buffering
                readgzfile($entry);
                $content = ob_get_contents(); // Store buffer in variable
                ob_end_clean(); // End buffering and clean up
            }
            $dataXML=@simplexml_load_string($content);
            if($dataXML)
            {
                printf("OK\n");
                $element["report_metadata"]=$dataXML->report_metadata;
                $element["policy_published"]=$dataXML->policy_published;
                foreach($dataXML->record as $record)
                {
                    $element["records"][] = $record;
                    $ip_length = strlen($record->row->source_ip);
                    if($ip_length > $max_ip_length)
                        $max_ip_length = $ip_length;
                }
                $element["file"]=$entry;
                $results[]=$element;
                unset($element);
            }
            else
            {
                printf("CANNOT BE PARSED\n");
            }
        }
    }
    closedir($handle);
}

// tri par date :
uasort($results,function ($a, $b) {
            return strnatcmp($a["report_metadata"]->date_range->begin,$b["report_metadata"]->date_range->begin);
        }
    );

$LAST="";
foreach($results as $element)
{
    $NEW=gmdate("Y-m-d", ''.$element["report_metadata"]->date_range->begin);
    if($LAST !== $NEW)
        echo "\n";
    $LAST = $NEW;
    printf("%s report for \033[36m %s \033[39m from %s '%s' : \n",
        $NEW,
        $element["policy_published"]->domain, // FOR
        $element["report_metadata"]->email, // FROM
        $element["file"]
        );
    // tri par ip source :
    usort($element["records"],function ($a, $b) {
                return strnatcmp($a->row->source_ip,$b->row->source_ip);
            }
        );
    $new_record=null;
    foreach($element["records"] as $record)
    {
        // le premier coup
        if($new_record === null)
        {
            $new_record = $record;
            continue;
        }
        // cumul si besoin
        if( strcmp($new_record->row->source_ip , $record->row->source_ip) === 0 )
        {
            $new_record->row->count += $record->row->count;
            $new_record->identifiers->envelope_to .= ", ". $record->identifiers->envelope_to;
            // echo "CNT".$new_record->row->count."\n";
            continue;
        }
        // sinon on affiche
        display_record($new_record, $max_ip_length);
        // next
        $new_record = $record;
    }
    display_record($new_record, $max_ip_length);
}

save_cache_resolved();
