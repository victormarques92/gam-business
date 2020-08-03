        jQuery(document).ready(function($) {
			

            function limpa_formulário_cep(obj) {
                // Limpa valores do formulário de cep.
                obj.closest('form').find(".cf7-cep-autofill__rua").val("");
                obj.closest('form').find(".cf7-cep-autofill__bairro").val("");
                obj.closest('form').find(".cf7-cep-autofill__cidade").val("");
                obj.closest('form').find(".cf7-cep-autofill__uf").val("");
            }
            
            //Quando o campo cep perde o foco.
            $(".cf7-cep-autofill").blur(function() {
				
				var obj = $(this);

                //Nova variável "cep" somente com dígitos.
                var cep = obj.val().replace(/\D/g, '');

                //Verifica se campo cep possui valor informado.
                if (cep != "") {

                    //Expressão regular para validar o CEP.
                    var validacep = /^[0-9]{8}$/;

                    //Valida o formato do CEP.
                    if(validacep.test(cep)) {

                        //Preenche os campos com "..." enquanto consulta webservice.
                        obj.closest('form').find(".cf7-cep-autofill__rua").val("...");
                        obj.closest('form').find(".cf7-cep-autofill__bairro").val("...");
                        obj.closest('form').find(".cf7-cep-autofill__cidade").val("...");
                        obj.closest('form').find(".cf7-cep-autofill__uf").val("...");

                        //Consulta o webservice viacep.com.br/
                        $.getJSON("https://viacep.com.br/ws/"+ cep +"/json/?callback=?", function(dados) {

                            if (!("erro" in dados)) {
                                //Atualiza os campos com os valores da consulta.
                                obj.closest('form').find(".cf7-cep-autofill__rua").val(dados.logradouro);
                                obj.closest('form').find(".cf7-cep-autofill__bairro").val(dados.bairro);
                                obj.closest('form').find(".cf7-cep-autofill__cidade").val(dados.localidade);
                                obj.closest('form').find(".cf7-cep-autofill__uf").val(dados.uf);
                            } //end if.
                            else {
                                //CEP pesquisado não foi encontrado.
                                limpa_formulário_cep(obj);
                                alert("CEP não encontrado.");
                            }
                        });
                    } //end if.
                    else {
                        //cep é inválido.
                        limpa_formulário_cep();
                        alert("Formato de CEP inválido.");
                    }
                } //end if.
                else {
                    //cep sem valor, limpa formulário.
                    limpa_formulário_cep();
                }
            });
        });