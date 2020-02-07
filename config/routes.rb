Rails.application.routes.draw do
  # For details on the DSL available within this file, see http://guides.rubyonrails.org/routing.html
  namespace :auth do
    post "apple", controller: :apple, action: :auth, format: false
  end
end
