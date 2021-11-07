from PyPDF2 import PdfFileWriter, PdfFileReader
from PyPDF2.generic import NameObject, createStringObject

def read(input_pdf):

    pdf_reader = PdfFileReader(input_pdf)
    print(pdf_reader.getDocumentInfo())
        
if __name__ == '__main__':            
    # read(input_pdf='ROSCON2019_Workshop_Aliasroboticscopy.pdf')
    read(input_pdf='AliasRobotics - RT_workshop_ROSCon_2019.pdf')
