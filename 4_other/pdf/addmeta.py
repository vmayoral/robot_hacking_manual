# pdf_encryption.py

from PyPDF2 import PdfFileWriter, PdfFileReader
from PyPDF2.generic import NameObject, createStringObject

def meta(input_pdf, output_pdf, value):

    pdf_writer = PdfFileWriter()
    pdf_reader = PdfFileReader(input_pdf)

    for page in range(pdf_reader.getNumPages()):
        pdf_writer.addPage(pdf_reader.getPage(page))

    # pdf_writer.encrypt(user_pwd=password, owner_pwd=None, 
    #                    use_128bit=True)

    infoDict = pdf_writer._info.getObject()

    infoDict.update({NameObject('/Version'): createStringObject(u'234ds2')})
    info = pdf_reader.documentInfo
    for key in info:
        infoDict.update({NameObject(key): createStringObject(info[key])})

    # add the grade
    # infoDict.update({NameObject('/Grade'): createStringObject(u'A+')})
    # infoDict.update({NameObject('/Grade2'): createStringObject(u'A+')})
    infoDict.update({NameObject('/Key'): createStringObject(value)})    

    with open(output_pdf, 'wb') as fh:
        pdf_writer.write(fh)
        
if __name__ == '__main__':
            
    meta(input_pdf='/Users/victor/Desktop/Apex.AI_Threat_Model_AliasRobotics.pdf',
            output_pdf='/Users/victor/Desktop/Apex.AI_Threat_Model_AliasRobotics_underNDA.pdf',
            value=u'HitachiVentures')
            