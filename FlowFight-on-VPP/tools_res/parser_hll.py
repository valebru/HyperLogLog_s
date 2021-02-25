import sys
import numbers

try:
	print("read file: \t" + str(sys.argv[1]))
	print("write file: \t" + str(sys.argv[2]))
	print("reference file: \t" + str(sys.argv[3]))

	filenamer = str(sys.argv[1])
	filenamew = str(sys.argv[2])
	filenameref = str(sys.argv[3])

	fr = open(filenamer, 'r')
	fref = open(filenameref, 'r')
	fw = open(filenamew, 'a')
except IndexError:
	print("Error: no Filename")
	sys.exit(2)

#experiment file parsing
val_line=[]
inside=False
element = {}
for line in fr:
        if (not line.find("==========V=============") and inside):
		inside=False
                val_line.append(element)
                element = {}

	if inside:
                tmp = line.split()
                element[tmp[1]] = float(tmp[0])
                #element.append(line.split()[0])
                #for s in line.split():
			#try:
				#if isinstance(float(s), numbers.Real):
			       # if s.is_digit(): 
					#element.append(s)
			#except ValueError: count = count

        if (not line.find("==========VVV=============") and not inside):
		inside=True



#REF_file inspection
ref_value = {}
inside=True
inside=False
for line in fref:
        if (not line.find("==========V=============") and inside):
		inside=False

	if inside:
            tmp = line.split()
            ref_value[tmp[1]] = float(tmp[0])

        if (not line.find("==========VVV=============") and not inside):
		inside=True



#PRECISION-ARE-AAE
f_prec=[]
f_are=[]
f_aae=[]
for trial in val_line:
    trial_keys = trial.keys()
    ref_keys = ref_value.keys()
    ref_k_value = sorted(ref_value, key=ref_value.get, reverse=True)[0:len(trial)]
    intersection_rr = [value for value in ref_k_value if value not in trial_keys] 
    #print(len(trial), len(intersection_rr), len(val_line))

    print("\n--------")
    print("Printing the first 5 elements not captured in the real first top-"+str(len(trial))+" ("+str(len(trial))+","+ str(len(intersection_rr))+")")
    print("--------")
    print("[key \t exact_value \t index_in_topk]")
    for value in intersection_rr[0:5]:
        index =0
        pos= 0
        for kvalue in ref_k_value:
            if kvalue==value: pos=index
            index +=1
        print(str(value) + "\t" + str(ref_value[value]) + "\t" + str(pos))
    #print(str(ref_k_value))
    corrected_keys = 0
    keys_counted = 0
    relative_error = 0
    absolute_error = 0
    for key_item in trial_keys:
        if key_item in ref_k_value:
            corrected_keys = corrected_keys +1

        if key_item in ref_keys:
            keys_counted = keys_counted + 1
            relative_error = relative_error + float(abs(trial[key_item]-ref_value[key_item])/(ref_value[key_item]+0.0))
            absolute_error = absolute_error + abs(trial[key_item]-ref_value[key_item])
    #print(float(corrected_keys),(len(trial)+0.0))
    f_prec.append(float(corrected_keys/(len(trial)+0.0)))
    f_are.append(relative_error/keys_counted)
    f_aae.append(absolute_error/keys_counted)

print("\n--------")
print("Summary:")
print("--------")
print("Precision: "+str(f_prec))
print("Relative error: "+str(f_are))
print("Absolute error: "+ str(f_aae))

for x,y,k in zip(f_prec, f_are, f_aae):
    str_tow = str(x) + " " + str(y) + " " + str(k) + " " + filenamer
    #print(str(str_tow))
    fw.write(str(str_tow) + '\n')


fr.close
fref.close
fw.close
