# pdf_encryption.py

from PyPDF2 import PdfFileWriter, PdfFileReader

def encrypt(input_pdf, output_pdf, password):

    pdf_writer = PdfFileWriter()

    pdf_reader = PdfFileReader(input_pdf)

    for page in range(pdf_reader.getNumPages()):

        pdf_writer.addPage(pdf_reader.getPage(page))

    pdf_writer.encrypt(user_pwd=password, owner_pwd=None, 

                       use_128bit=True)

    with open(output_pdf, 'wb') as fh:

        pdf_writer.write(fh)
        
if __name__ == '__main__':

    encrypt(input_pdf='ROSCON2019_Workshop_Aliasroboticscopy.pdf',
            output_pdf='encrypted.pdf',
            password='blowfish')
